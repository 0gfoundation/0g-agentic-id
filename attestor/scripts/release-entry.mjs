#!/usr/bin/env node
// Generate an environment's attestor release file (ATTESTOR_RELEASES_FILE)
// from the repository's CHANGELOG.md and that environment's parameters.
//
//   node attestor/scripts/release-entry.mjs \
//     --changelog CHANGELOG.md \
//     --params releases/testnet.json \
//     --min-days 14 \
//     [--out <dir>/releases.json]
//
// The parameters file lists, per released version, what differs between
// environments: when it is published there, and which images it replaces
// until when.
//
//   {"releases": [{"version": "0.5.0", "published_at": "…Z",
//                  "migrate": [{"framework": "openclaw", "image_hash": "0x…",
//                               "until": "…Z", "urgent": false}]}]}
//
// Each release's `notes` are its CHANGELOG.md section (`## <version>`). An
// entry may carry its own `notes` instead, for a test release that has no
// changelog section. A section still headed `(unreleased)` is refused.
//
// The attestor's own checks are repeated here, plus the transition period:
// with --min-days, an entry's `until` must be at least that many days after
// `published_at` (30 on mainnet, 14 on testnet), unless the entry is urgent.
//
// Without --out the file goes to stdout. With --out it is written next to the
// target and renamed over it, so a mounted directory sees it whole.

import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

const MAX_NOTES = 4000;
const VERSION = /^[A-Za-z0-9._+-]{1,64}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
const DAY_MS = 86_400_000;

/** A problem with the inputs; the command prints it and exits 1. */
export class ReleaseEntryError extends Error {}

function fail(message) {
  throw new ReleaseEntryError(message);
}

function die(message) {
  process.stderr.write(`release-entry: ${message}\n`);
  process.exit(1);
}

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) fail(`unexpected argument ${a}`);
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) fail(`${a} needs a value`);
    out[a.slice(2)] = v;
    i++;
  }
  return out;
}

/** CHANGELOG.md sections by version: `## <version>` or `## <version> (unreleased)`. */
export function sections(markdown) {
  const out = new Map();
  let current = null;
  for (const line of markdown.split('\n')) {
    const h = /^## (\S+)(?:\s+\(([^)]*)\))?\s*$/.exec(line);
    if (h) {
      current = { version: h[1], unreleased: h[2] === 'unreleased', lines: [] };
      out.set(current.version, current);
    } else if (line.startsWith('# ')) {
      current = null;
    } else if (current) {
      current.lines.push(line);
    }
  }
  for (const s of out.values()) s.text = s.lines.join('\n').trim();
  return out;
}

function iso(v, what) {
  const t = typeof v === 'string' ? Date.parse(v) : NaN;
  if (Number.isNaN(t)) fail(`${what} must be an ISO time, got ${JSON.stringify(v)}`);
  return t;
}

export function build(changelog, params, minDays) {
  const notes = sections(changelog);
  const seen = new Set();
  const releases = [];
  if (!params || !Array.isArray(params.releases)) fail('the parameters file must be {"releases": [...]}');
  for (const p of params.releases) {
    const version = p.version;
    if (typeof version !== 'string' || !VERSION.test(version)) fail(`version ${JSON.stringify(version)} must be 1-64 of A-Z a-z 0-9 . _ + -`);
    if (seen.has(version)) fail(`version ${version} appears twice`);
    seen.add(version);
    let text = p.notes;
    if (text === undefined) {
      const s = notes.get(version);
      if (!s) fail(`CHANGELOG.md has no section "## ${version}" (or give the entry its own "notes")`);
      if (s.unreleased) fail(`CHANGELOG.md still marks ${version} (unreleased)`);
      text = s.text;
    }
    if (typeof text !== 'string' || !text.trim()) fail(`${version}: the notes are empty`);
    if (Buffer.byteLength(text) > MAX_NOTES) fail(`${version}: the notes are ${Buffer.byteLength(text)} bytes; the attestor takes at most ${MAX_NOTES}`);
    const published = iso(p.published_at, `${version}: published_at`);
    const migrate = [];
    const images = new Set();
    for (const m of p.migrate ?? []) {
      if (typeof m.framework !== 'string' || !m.framework.trim() || m.framework.length > 64) fail(`${version}: framework must be 1-64 characters`);
      if (typeof m.image_hash !== 'string' || !HASH.test(m.image_hash) || /^0x0{64}$/.test(m.image_hash)) fail(`${version}: image_hash must be a non-zero 0x + 64 hex`);
      const key = m.image_hash.toLowerCase();
      if (images.has(key)) fail(`${version}: image ${m.image_hash} appears twice`);
      images.add(key);
      const until = iso(m.until, `${version}: until`);
      if (until <= published) fail(`${version}: until must be after published_at`);
      const urgent = m.urgent === true;
      if (minDays && !urgent && until - published < minDays * DAY_MS) {
        fail(`${version}: the ${m.framework} image's transition period is ${((until - published) / DAY_MS).toFixed(1)} days; this environment needs at least ${minDays} (or mark it urgent)`);
      }
      migrate.push({ framework: m.framework, image_hash: m.image_hash, until: m.until, ...(urgent ? { urgent: true } : {}) });
    }
    releases.push({ version, published_at: p.published_at, notes: text, migrate });
  }
  return { releases };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const a = args(process.argv.slice(2));
    if (!a.changelog || !a.params) fail('usage: release-entry.mjs --changelog CHANGELOG.md --params <env>.json [--min-days N] [--out FILE]');
    const minDays = a['min-days'] === undefined ? 0 : Number(a['min-days']);
    if (!Number.isFinite(minDays) || minDays < 0) fail('--min-days must be a number of days');
    let params;
    try { params = JSON.parse(readFileSync(a.params, 'utf8')); } catch (e) { fail(`cannot read ${a.params}: ${e.message}`); }
    const file = `${JSON.stringify(build(readFileSync(a.changelog, 'utf8'), params, minDays), null, 2)}\n`;
    if (!a.out) {
      process.stdout.write(file);
    } else {
      const tmp = join(dirname(a.out), `.${basename(a.out)}.tmp`);
      writeFileSync(tmp, file);
      renameSync(tmp, a.out);
      process.stderr.write(`release-entry: wrote ${a.out}\n`);
    }
  } catch (e) {
    die(e instanceof ReleaseEntryError ? e.message : String(e));
  }
}
