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
