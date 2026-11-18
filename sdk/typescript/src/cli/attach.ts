/**
 * @file attach.ts
 * @description `/attach`: files and images staged for the owner's next
 * message.
 *
 * An image (recognized by its bytes: PNG, JPEG, WebP, GIF) goes with the
 * message itself; any other file is uploaded first (`uploadFile`, 0g-harness
 * `POST /v1/files`) and the message names the path it landed at. The limits
 * are 0g-harness's (docs/PROTOCOL.md there), checked here so a refusal comes
 * when the file is staged, not after the message is typed.
 */

import { closeSync, openSync, readFileSync, readSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import type { AgentClient, ChatImage } from '../AgentClient';

export const ATTACH_LIMITS = {
  imageBytes: 10 << 20,
  imagesPerMessage: 8,
  messageImageBytes: 32 << 20,
  fileBytes: 25 << 20,
} as const;

/** One staged attachment. `image` is set when its bytes are an image. */
export interface Staged {
  path: string;
  name: string;
  bytes: number;
  image?: ChatImage['mediaType'];
}

/** `~` and `~/…` as the user's home. */
export function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return join(homedir(), p.slice(2));
  return p;
}

/** The image type these leading bytes are, or undefined. */
export function sniffImage(head: Uint8Array): ChatImage['mediaType'] | undefined {
  const at = (i: number, bytes: number[]): boolean => bytes.every((b, k) => head[i + k] === b);
  if (at(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  if (at(0, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (at(0, [0x47, 0x49, 0x46, 0x38])) return 'image/gif';
  if (at(0, [0x52, 0x49, 0x46, 0x46]) && at(8, [0x57, 0x45, 0x42, 0x50])) return 'image/webp';
  return undefined;
}

function head(path: string): Uint8Array {
  const fd = openSync(path, 'r');
  try {
    const buf = new Uint8Array(16);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n);
  } finally {
    closeSync(fd);
  }
}

const size = (n: number): string => (n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / (1 << 20)).toFixed(1)} MiB`);

/**
 * Stage one path for the next message, against what is staged already.
 * Throws an Error whose message says why it cannot go.
 */
export function stageFile(raw: string, staged: readonly Staged[]): Staged {
  const path = resolve(expandHome(raw));
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new Error(`${raw}: no such file`);
  }
  if (!st.isFile()) throw new Error(`${raw}: not a regular file`);
  if (staged.some((s) => s.path === path)) throw new Error(`${raw}: already attached`);
  const image = sniffImage(head(path));
  if (image) {
    if (st.size > ATTACH_LIMITS.imageBytes) throw new Error(`${raw}: an image is at most ${size(ATTACH_LIMITS.imageBytes)} (this one is ${size(st.size)})`);
    const images = staged.filter((s) => s.image);
    if (images.length + 1 > ATTACH_LIMITS.imagesPerMessage) throw new Error(`${raw}: at most ${ATTACH_LIMITS.imagesPerMessage} images per message`);
    const total = images.reduce((n, s) => n + s.bytes, 0) + st.size;
    if (total > ATTACH_LIMITS.messageImageBytes) throw new Error(`${raw}: the images of one message are at most ${size(ATTACH_LIMITS.messageImageBytes)} together`);
  } else if (st.size > ATTACH_LIMITS.fileBytes) {
    throw new Error(`${raw}: a file is at most ${size(ATTACH_LIMITS.fileBytes)} (this one is ${size(st.size)})`);
  }
  return { path, name: basename(path), bytes: st.size, ...(image ? { image } : {}) };
}

/** One line per staged attachment. */
export function describeStaged(staged: readonly Staged[]): string[] {
  return staged.map((s, i) => `  ${i + 1}. ${s.name}  ${s.image ? `image (${s.image.slice(6)})` : 'file'}, ${size(s.bytes)}`);
}

/**
 * What a message with these attachments sends: the images, and the text
 * with a `[file uploaded: <path>]` line for each other file, uploaded first.
 */
export async function prepareAttachments(
  staged: readonly Staged[],
  text: string,
  client: Pick<AgentClient, 'uploadFile'>,
  onUploaded?: (s: Staged, path: string) => void,
): Promise<{ text: string; images: ChatImage[] }> {
  const images: ChatImage[] = [];
  let out = text;
  for (const s of staged) {
    const data = readFileSync(s.path);
    if (s.image) {
      images.push({ mediaType: s.image, data: data.toString('base64'), name: s.name });
      continue;
    }
    if (!client.uploadFile) throw new Error('this agent takes no files: its framework has no upload route');
    const up = await client.uploadFile(s.name, new Uint8Array(data.buffer, data.byteOffset, data.length));
    onUploaded?.(s, up.path);
    out += `${out ? '\n' : ''}[file uploaded: ${up.path}]`;
  }
  return { text: out, images };
}

/**
 * Where a file dragged into the terminal can come from: the user's home, an
 * external volume, and the temporary folders (macOS screenshots land in
 * `/var/folders`). A path elsewhere (`/etc/hosts`) is text the user typed,
 * never uploaded.
 */
export function dropRoots(): string[] {
  return [homedir(), '/Volumes', '/tmp', '/private/tmp', '/var/folders', '/private/var/folders', '/media', '/mnt'];
}

/** One file a message carries, as it appeared in the typed text. */
export interface DroppedFile {
  path: string;
  raw: string;
}

function droppable(raw: string, roots: readonly string[]): string | undefined {
  const path = resolve(expandHome(raw));
  if (!roots.some((r) => path.startsWith(r.endsWith('/') ? r : `${r}/`))) return undefined;
  try {
    return statSync(path).isFile() ? path : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A typed message split into its text and the local files in it: a file
 * dragged into the terminal leaves its path in the line (`/a/My\ File.png`,
 * or quoted, `'/a/My File.png'`), and so does a pasted path. A path counts
 * when it starts a word, names an existing regular file under
 * {@link dropRoots}, and ends the word. A path inside backticks stays text.
 */
export function findDroppedFiles(line: string, roots: readonly string[] = dropRoots()): Array<string | DroppedFile> {
  const parts: Array<string | DroppedFile> = [];
  let text = '';
  const flush = (): void => {
    if (text) parts.push(text);
    text = '';
  };
  const wordEnd = (k: number): boolean => k >= line.length || /\s/.test(line[k]);
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    const starts = i === 0 || /\s/.test(line[i - 1]);
    if (c === '`') {
      const j = line.indexOf('`', i + 1);
      const end = j === -1 ? line.length : j + 1;
      text += line.slice(i, end);
      i = end;
      continue;
    }
    if (starts && (c === "'" || c === '"')) {
      const j = line.indexOf(c, i + 1);
      const path = j > i + 1 && wordEnd(j + 1) ? droppable(line.slice(i + 1, j), roots) : undefined;
      if (path) {
        flush();
        parts.push({ path, raw: line.slice(i, j + 1) });
        i = j + 1;
        continue;
      }
    }
    if (starts && (c === '/' || (c === '~' && line[i + 1] === '/'))) {
      let value = '';
      let k = i;
      while (k < line.length && !/\s/.test(line[k])) {
        if (line[k] === '\\' && k + 1 < line.length) {
          value += line[k + 1];
          k += 2;
          continue;
        }
        value += line[k];
        k++;
      }
      const path = droppable(value, roots);
      if (path) {
        flush();
        parts.push({ path, raw: line.slice(i, k) });
        i = k;
        continue;
      }
    }
    text += c;
    i++;
  }
  flush();
  return parts;
}

/**
 * Stage the files {@link findDroppedFiles} found, after what is staged
 * already, and give back the message text: an image is named where its path
 * was (`[image: <name>]`); another file's path is left out, as
 * {@link prepareAttachments} names it once uploaded. When one cannot go, the
 * ones staged here are dropped again and the reason comes back.
 */
export function stageDropped(
  parts: ReadonlyArray<string | DroppedFile>,
  staged: Staged[],
  onAttached?: (s: Staged) => void,
): { text: string } | { refused: string } {
  const before = staged.length;
  let text = '';
  for (const p of parts) {
    if (typeof p === 'string') {
      text += p;
      continue;
    }
    try {
      const one = stageFile(p.path, staged);
      staged.push(one);
      onAttached?.(one);
      if (one.image) text += `[image: ${one.name}]`;
    } catch (err) {
      staged.length = before;
      return { refused: (err as Error).message };
    }
  }
  return { text: text.replace(/[ \t]{2,}/g, ' ').trim() };
}

/** Tab completion of a path being typed after `/attach`. */
export function completePath(word: string): string[] {
  const typed = expandHome(word);
  const dir = typed.endsWith('/') ? typed : dirname(typed);
  const base = typed.endsWith('/') ? '' : basename(typed);
  const shown = word.endsWith('/') ? word : word.slice(0, word.length - basename(word).length);
  let names: string[];
  try {
    names = readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.name.startsWith(base) && (base.startsWith('.') || !e.name.startsWith('.')))
      .map((e) => `${shown}${e.name}${e.isDirectory() ? '/' : ''}`);
  } catch {
    return [];
  }
  return names.sort();
}
