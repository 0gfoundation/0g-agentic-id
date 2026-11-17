/**
 * `/files` and `/download` (0g-harness): the files the agent hands over in its
 * `~/outbox`, or the owner's own files in its file inbox `~/inbox`, saved
 * locally. A download never
 * overwrites a local file: a taken name gets "-1", "-2", … before its
 * extension.
 */
import { closeSync, existsSync, openSync, statSync, writeSync } from 'node:fs';
import { basename, extname, join, resolve } from 'node:path';
import type { AgentFile, AgentFileDir } from '../AgentClient';
import { expandHome } from './attach';

/** `/download` argument → where it comes from: `inbox/<name>` names a file in the agent's file inbox (the owner's own), anything else the outbox. */
export function parseDownloadName(arg: string): { dir: AgentFileDir; name: string } {
  if (arg.startsWith('inbox/')) return { dir: 'inbox', name: arg.slice('inbox/'.length) };
  if (arg.startsWith('outbox/')) return { dir: 'outbox', name: arg.slice('outbox/'.length) };
  return { dir: 'outbox', name: arg };
}

/** A local file name for a remote one: its last segment, no control characters, no leading dots. */
export function localName(name: string): string {
  const n = basename(name.replace(/\\/g, '/')).replace(/[\u0000-\u001f\u007f]/g, '_').replace(/^\.+/, '').trim();
  return n || 'download';
}

/**
 * Write bytes to a new local file and return its path. dest: undefined (the
 * current directory), an existing directory, or a file path. Never over an
 * existing file.
 */
export function saveDownload(bytes: Uint8Array, name: string, dest?: string, cwd: string = process.cwd()): string {
  let dir: string;
  let file: string;
  if (!dest) {
    dir = cwd;
    file = localName(name);
  } else {
    const p = resolve(cwd, expandHome(dest));
    if (existsSync(p) && statSync(p).isDirectory()) {
      dir = p;
      file = localName(name);
    } else {
      dir = resolve(p, '..');
      file = basename(p) || localName(name);
    }
  }
  const ext = extname(file);
  const stem = file.slice(0, file.length - ext.length) || 'download';
  for (let i = 0; i < 10000; i++) {
    const path = join(dir, i === 0 ? file : `${stem}-${i}${ext}`);
    let fd: number;
    try {
      fd = openSync(path, 'wx', 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') continue;
      throw err;
    }
    try {
      let off = 0;
      while (off < bytes.length) off += writeSync(fd, bytes, off, bytes.length - off);
    } finally {
      closeSync(fd);
    }
    return path;
  }
  throw new Error(`no free local name for ${file}`);
}

const size = (n: number): string =>
  n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / (1 << 20)).toFixed(1)} MiB`;

/** `/files` lines: name, size, time. */
export function renderFiles(files: readonly AgentFile[]): string[] {
  const w = Math.max(4, ...files.map((f) => f.name.length));
  return files.map((f) => `  ${f.name.padEnd(w)}  ${size(f.bytes).padStart(10)}  ${f.mtime.replace('T', ' ').replace(/\.\d+Z$/, 'Z')}`);
}
