/**
 * @file update.ts
 * @description `0g-agentdna update` — self-update the CLI (it ships inside
 * the SDK npm package). Compares the running version against the npm
 * registry's latest and runs `npm install -g <pkg>@<latest>` when behind.
 *
 * A development copy (git checkout / npm link — resolved path outside any
 * node_modules) is never npm-overwritten: the command reports the versions
 * and tells you to `git pull && npm run build` instead.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { CliError } from '../errors';
import { emitOk, note, print } from '../envelope';
import type { CommandContext } from '../types';

/** The legacy launcher owns the global bin links when installed through the
 *  old package's updater. Update that package so npm can replace its own links
 *  and bring along the matching AgentDNA dependency without EEXIST collisions. */
export function selfPackage(entrypoint: string | undefined = process.argv[1]): { name: string; version: string; dir: string } {
  if (entrypoint) {
    try {
      const dir = dirname(realpathSync(entrypoint));
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as {
        name: string; version: string; agentdnaLegacyBridge?: boolean;
      };
      if (pkg.name === '@0gfoundation/0g-agenticid-sdk' && pkg.agentdnaLegacyBridge === true) {
        return { name: pkg.name, version: pkg.version, dir };
      }
    } catch { /* regular CLI entrypoints do not sit next to a bridge manifest */ }
  }
  const dir = join(__dirname, '..', '..', '..'); // dist/cli/commands → package root
  const raw = readFileSync(join(dir, 'package.json'), 'utf8');
  const pkg = JSON.parse(raw) as { name: string; version: string };
  return { name: pkg.name, version: pkg.version, dir };
}

export async function run(ctx: CommandContext): Promise<void> {
  const self = selfPackage();
  note(`checking ${self.name} against the npm registry…`);
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(self.name)}/latest`).catch((e: Error) => {
    throw new CliError('UNKNOWN', `npm registry unreachable: ${e.message}`, { remedy: 'check network and retry' });
  });
  if (!res.ok) {
    throw new CliError('UNKNOWN', `npm registry returned HTTP ${res.status} for ${self.name}`, { remedy: 'retry later' });
  }
  const latest = ((await res.json()) as { version?: string }).version;
  if (!latest) throw new CliError('UNKNOWN', 'npm registry response had no version field');

  // numeric x.y.z compare: <0 behind, 0 equal, >0 ahead of the registry
  const cmp = ((a: string, b: string): number => {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
    return 0;
  })(self.version, latest);

  const dev = !self.dir.includes('node_modules');
  if (cmp >= 0) {
    if (ctx.json) { emitOk({ name: self.name, current: self.version, latest, updated: false, dev }); return; }
    if (cmp === 0) print(`up to date — ${self.name} ${self.version}`);
    else print(`ahead of the registry — running ${self.version}, npm latest is ${latest} (not yet published)`);
    return;
  }
  if (dev) {
    if (ctx.json) { emitOk({ name: self.name, current: self.version, latest, updated: false, dev }); return; }
    print(`current ${self.version} · latest ${latest}`);
    print(`this is a development copy (${self.dir}) — update it with: git pull && npm run build`);
    return;
  }
  if (ctx.json) {
    // --json is machine mode: report, don't spawn an interactive installer.
    emitOk({ name: self.name, current: self.version, latest, updated: false, dev, remedy: `npm install -g ${self.name}@${latest}` });
    return;
  }
  print(`current ${self.version} · latest ${latest} — updating…`);
  const r = spawnSync('npm', ['install', '-g', `${self.name}@${latest}`], { stdio: 'inherit' });
  if (r.status !== 0) {
    throw new CliError('UNKNOWN', `npm install -g exited with ${r.status ?? 'signal'}`, {
      remedy: `run manually: npm install -g ${self.name}@${latest} (may need elevated permissions)`,
    });
  }
  print(`updated ${self.name} ${self.version} → ${latest}`);
}
