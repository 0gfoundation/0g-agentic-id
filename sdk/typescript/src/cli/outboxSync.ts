/**
 * New files in the agent's `~/outbox` come to the owner by themselves (0g-harness):
 * each one is saved to `~/agentdna/<agentId>/outbox/<name>` on this machine.
 * A file already saved there with the same content is not saved again; a
 * different file of the same name is never overwritten: the new one gets
 * "-1", "-2", … before its extension (saveDownload). Files over the download
 * limit are skipped and reported once.
 *
 * Once a file is saved and its size (and hash, when the listing has one)
 * match the outbox's, it is removed from the outbox (`remove`): the owner
 * has it, and the agent's disk does not keep a copy. A runtime without the
 * delete route keeps its files; deleting is then not tried again this
 * session.
 *
 * Which versions of which files were saved is kept next to that folder
 * (`outbox-saved.json`: name → size, time, hash, local path), so a check
 * downloads only what changed. Failed transfers and remote cleanup retry
 * with backoff; cleanup rechecks the saved local copy before deleting.
 * Without the index (lost, unreadable) a check downloads
 * the outbox again and the content comparison keeps it from saving copies.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { extname, join, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { AgentFile } from '../AgentClient';
import { cleanCell } from './commands/cells';
import { DOWNLOAD_MAX_BYTES, localName, saveDownload, size } from './download';

/** How often the session looks at the outbox. */
export const OUTBOX_POLL_MS = 30_000;

/** What a check did with one file. */
export interface OutboxEvent {
  kind: 'saved' | 'skipped' | 'failed';
  /** Its name in the outbox. */
  name: string;
  bytes: number;
  /** Where it was saved. */
  path?: string;
  error?: string;
}

interface Saved { bytes: number; mtime: string; sha256?: string; path?: string }

/** This machine's folder for one agent's files: `~/agentdna/<agentId>`. */
export function agentFilesDir(agentId: string, home: string = homedir()): string {
  return join(home, 'agentdna', agentId);
}

export interface OutboxSync {
  /** Look at the outbox now (a check already running is shared). With
   *  saving on, new files are saved; off, they are only counted. */
  check(): Promise<OutboxEvent[]>;
  /** New files the last check counted and did not save (saving off), less
   *  those `/files` has listed since. */
  unseen(): number;
  /** `/files` listed these: not new any more. */
  listed(files: readonly AgentFile[]): void;
  /** Where files are saved. */
  readonly dir: string;
}

export function makeOutboxSync(o: {
  agentId: string;
  home?: string;
  list(): Promise<AgentFile[]>;
  download(name: string): Promise<Uint8Array>;
  /** Whether new files are saved (else only counted). */
  auto(): boolean;
  /** Remove a saved file from the outbox; see {@link AgentClient.deleteFile}. */
  remove?(name: string): Promise<'deleted' | 'missing' | 'unsupported'>;
  /** Clock for retry scheduling. */
  now?: () => number;
}): OutboxSync {
  const base = agentFilesDir(o.agentId, o.home);
  const dir = join(base, 'outbox');
  const indexFile = join(base, 'outbox-saved.json');
  const index = readIndex(indexFile);
  // Versions reported this session (skipped, failed) and listed by /files.
  const reported = new Set<string>();
  const shown = new Set<string>();
  let unseen: AgentFile[] = [];
  let running: Promise<OutboxEvent[]> | null = null;
  let canRemove = !!o.remove;
  const now = o.now ?? Date.now;
  const retries = new Map<string, { attempts: number; at: number }>();
  const ready = (key: string): boolean => (retries.get(key)?.at ?? 0) <= now();
  const failed = (key: string): void => {
    const attempts = (retries.get(key)?.attempts ?? 0) + 1;
    retries.set(key, { attempts, at: now() + Math.min(300_000, OUTBOX_POLL_MS * 2 ** Math.min(attempts - 1, 4)) });
  };

  const version = (f: AgentFile): string => `${f.name}\u0000${f.bytes}\u0000${f.mtime}`;
  const isNew = (f: AgentFile): boolean => {
    const s = index[f.name];
    return !s || s.bytes !== f.bytes || s.mtime !== f.mtime || (!!f.sha256 && !!s.sha256 && f.sha256 !== s.sha256);
  };

  async function removeSaved(f: AgentFile): Promise<void> {
    const key = `delete:${version(f)}`;
    if (!canRemove || !ready(key)) return;
    const saved = index[f.name];
    if (!saved?.path || saved.bytes !== f.bytes || saved.mtime !== f.mtime || !saved.sha256 || (f.sha256 && saved.sha256 !== f.sha256)) return;
    // The owner may have moved, removed or edited the local file since a
    // failed DELETE. An index entry alone is not a delivered copy.
    try {
      const bytes = readFileSync(saved.path);
      if (bytes.length !== saved.bytes || createHash('sha256').update(bytes).digest('hex') !== saved.sha256) return;
    } catch { return; }
    try {
      if ((await o.remove!(f.name)) === 'unsupported') canRemove = false;
      retries.delete(key);
    } catch { failed(key); }
  }

  async function run(): Promise<OutboxEvent[]> {
    const files = (await o.list()).reverse(); // oldest first
    const present = new Set(files.map(version));
    for (const key of reported) if (!present.has(key)) reported.delete(key);
    for (const key of shown) if (!present.has(key)) shown.delete(key);
    const versions = new Set(files.flatMap((f) => [`download:${version(f)}`, `delete:${version(f)}`]));
    for (const key of retries.keys()) if (!versions.has(key)) retries.delete(key);
    const events: OutboxEvent[] = [];
    if (!o.auto()) {
      unseen = files.filter((f) => isNew(f) && !reported.has(version(f)) && !shown.has(version(f)));
      return events;
    }
    unseen = [];
    for (const f of files) {
      if (!isNew(f)) { await removeSaved(f); continue; }
      const key = `download:${version(f)}`;
      if (!ready(key) || (reported.has(version(f)) && !retries.has(key))) continue;
      if (f.bytes > DOWNLOAD_MAX_BYTES) {
        reported.add(version(f));
        events.push({ kind: 'skipped', name: f.name, bytes: f.bytes });
        continue;
      }
      try {
        const bytes = await o.download(f.name);
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        mkdirSync(dir, { recursive: true });
        const have = sameFile(dir, f.name, bytes.length, sha256);
        const path = have ?? saveDownload(bytes, f.name, dir);
        index[f.name] = { bytes: bytes.length, mtime: f.mtime, sha256, path };
        writeIndex(indexFile, index);
        retries.delete(key);
        if (!have) events.push({ kind: 'saved', name: f.name, bytes: bytes.length, path });
        // The owner has it: take it off the agent's disk, unless what came
        // down is not what the listing described (it changed meanwhile).
        if (bytes.length === f.bytes && (!f.sha256 || f.sha256 === sha256)) await removeSaved(f);
      } catch (e) {
        failed(key);
        if (!reported.has(version(f))) events.push({ kind: 'failed', name: f.name, bytes: f.bytes, error: (e as Error).message });
        reported.add(version(f));
      }
    }
    return events;
  }

  return {
    dir,
    check() {
      running ??= run().finally(() => { running = null; });
      return running;
    },
    unseen: () => unseen.filter((f) => !shown.has(version(f))).length,
    listed(files) {
      for (const f of files) shown.add(version(f));
    },
  };
}

/** A file in `dir` that is `name` (or `name` saved under -1, -2, …) with this content, if any. */
function sameFile(dir: string, name: string, bytes: number, sha256: string): string | null {
  const file = localName(name);
  const ext = extname(file);
  const stem = file.slice(0, file.length - ext.length) || 'download';
  const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const same = new RegExp(`^${esc(stem)}(?:-\\d+)?${esc(ext)}$`);
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return null;
  }
  for (const n of names) {
    if (!same.test(n)) continue;
    const p = join(dir, n);
    try {
      const st = statSync(p);
      if (!st.isFile() || st.size !== bytes) continue;
      if (createHash('sha256').update(readFileSync(p)).digest('hex') === sha256) return p;
    } catch {
      // gone or unreadable: not this one
    }
  }
  return null;
}

function readIndex(file: string): Record<string, Saved> {
  try {
    const j = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    return j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, Saved>) : {};
  } catch {
    return {};
  }
}

function writeIndex(file: string, index: Record<string, Saved>): void {
  try {
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(index, null, 2)}\n`, { mode: 0o600 });
    renameSync(tmp, file);
  } catch {
    // The files are saved; without the record the next session compares content instead.
  }
}

/** `path` with the home folder written as `~`. */
export function tildePath(path: string, home: string = homedir()): string {
  return path === home || path.startsWith(home + sep) ? `~${path.slice(home.length)}` : path;
}

/**
 * Whether the terminal shows OSC 8 hyperlinks: FORCE_HYPERLINK=1|0 decides
 * when set; otherwise the terminals known to (iTerm2, WezTerm, VS Code,
 * Ghostty, kitty, Windows Terminal, VTE-based ones such as GNOME Terminal,
 * Konsole, Alacritty) on a terminal.
 */
export function supportsHyperlinks(env: NodeJS.ProcessEnv = process.env, isTTY = !!process.stdout.isTTY): boolean {
  const force = env.FORCE_HYPERLINK;
  if (force !== undefined && force !== '') return !/^(0|false|no|off)$/i.test(force);
  if (!isTTY || env.TERM === 'dumb') return false;
  if (env.TMUX || env.STY) return false; // a multiplexer may not pass the sequence on
  const program = env.TERM_PROGRAM ?? '';
  if (program === 'iTerm.app') {
    const [major, minor] = (env.TERM_PROGRAM_VERSION ?? '0.0').split('.').map(Number);
    return major > 3 || (major === 3 && minor >= 1);
  }
  if (['WezTerm', 'vscode', 'ghostty', 'Hyper', 'Tabby'].includes(program)) return true;
  if (env.WT_SESSION || env.KITTY_WINDOW_ID || env.KONSOLE_VERSION || env.ALACRITTY_WINDOW_ID || env.DOMTERM) return true;
  if (env.TERM === 'xterm-kitty' || env.TERM === 'alacritty' || env.TERM === 'xterm-ghostty') return true;
  return Number(env.VTE_VERSION ?? 0) >= 5000;
}

/** `text` as an OSC 8 link to a local file, when `on`; plain text otherwise. */
export function fileLink(text: string, path: string, on: boolean): string {
  return on ? `\x1b]8;;${pathToFileURL(path).href}\x1b\\${text}\x1b]8;;\x1b\\` : text;
}

/** One check's result as the session prints it. `links`: the path as a hyperlink. */
export function renderOutboxEvent(e: OutboxEvent, links: boolean, home: string = homedir()): string {
  const name = cleanCell(e.name);
  if (e.kind === 'skipped') {
    return `${name} (${size(e.bytes)}) is over the ${size(DOWNLOAD_MAX_BYTES)} download limit: not saved\n`;
  }
  if (e.kind === 'failed') {
    return `could not save ${name}: ${cleanCell(e.error ?? 'no reason given')} — will retry; /download ${name} tries now\n`;
  }
  const path = e.path ?? '';
  const renamed = localName(e.name) !== path.slice(path.lastIndexOf(sep) + 1);
  return `saved ${name} → ${fileLink(cleanCell(tildePath(path, home)), path, links)}${renamed ? ` (another file named ${name} is already there)` : ''}\n`;
}
