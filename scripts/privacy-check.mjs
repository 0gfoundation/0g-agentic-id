#!/usr/bin/env node
// privacy-check — keep private information out of a public repository.
//
//   node scripts/privacy-check.mjs --staged   the pre-commit hook: the lines a
//                                             commit adds, and the names of the
//                                             files it adds
//   node scripts/privacy-check.mjs --all      every tracked file (CI, audits)
//
// What it refuses: private keys and seed phrases, API keys and tokens, paths
// that name a person's machine, personal email addresses, public IP
// addresses, and files that hold secrets by convention (.env, *.pem, …).
//
// Exceptions, for content that only looks private:
//   - a line ending with the marker `privacy-check: allow` (fixtures in code);
//   - .privacy-check.json at the repository root:
//       { "ignorePaths": ["vendor/", "**/*.snap"],
//         "allow": [{ "sha256": "<fingerprint>", "note": "why it is not private" }] }
//     A fingerprint is the sha256 of the value itself (the key, the token, the
//     address), so the file never holds the value. Every finding prints its
//     fingerprint: allowing a genuine fixture is a copy.
//   - built in: lockfiles and minified bundles, loopback / private /
//     documentation IP ranges, and the Anvil/Hardhat default key published in
//     every Foundry and Hardhat guide.
//
// Findings are printed masked: the check never repeats a secret in full.

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

export const ALLOW_MARKER = 'privacy-check: allow'
export const CONFIG_FILE = '.privacy-check.json'

// Machine-written or minified: lockfiles hold registry URLs and checksums,
// minified bundles are third-party code full of random-looking runs.
const SKIP_FILES = /(^|\/)(npm-shrinkwrap\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|\.privacy-check\.json)$|\.min\.(js|css)$/

// Files that hold secrets by convention, refused by name.
const SECRET_FILE = /(^|\/)(\.env(\.(?!example$)[^/]+)?|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|[^/]+\.(pem|key|p12|pfx|keystore|jks)|apikey|credentials(\.json)?|[^/]+\.secret)$/i

// Email domains that identify no person.
const EMAIL_OK = /@(example\.(com|org|net)|users\.noreply\.github\.com|anthropic\.com)$/i
// Not public: loopback, "this network", private (RFC 1918), link-local,
// shared address space, broadcast, and the documentation ranges (RFC 5737).
const IP_OK = /^(127\.|0\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|255\.255\.255\.255$)/

// The Anvil/Hardhat default account #0 key, from the published test mnemonic.
const PUBLIC_TEST_VALUES = new Set(['ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'])

export const RULES = [
  { id: 'private-key-block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  // A 64-hex value next to a word that makes it a key, not a hash.
  { id: 'hex-private-key', value: (m) => m.slice(-64).toLowerCase(), re: /(?:priv(?:ate)?[_ -]?key|secret|_priv\b|privkey|mnemonic|seed)\W{0,6}(?:[\w"' ]{0,20}[:=]\s*)?["']?(?:0x)?[0-9a-fA-F]{64}\b/i },
  { id: 'seed-phrase', value: (m) => (m.match(/(?:[a-z]{3,8} ){11,23}[a-z]{3,8}$/i) || [m])[0].toLowerCase(), re: /(?:mnemonic|seed phrase|recovery phrase)\W{1,6}["']?(?:[a-z]{3,8} ){11,23}[a-z]{3,8}/i },
  { id: 'api-key', value: (m) => m, re: /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{36})/ },
  { id: 'jwt', value: (m) => m, re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { id: 'bearer-token', value: (m) => m.replace(/^Bearer\s+/, ''), re: /\bBearer\s+[A-Za-z0-9._~+/=-]{32,}/ },
  { id: 'local-path', re: /\/Users\/[A-Za-z0-9._-]+\/|\/home\/(?!agent\/|runner\/|node\/)[A-Za-z0-9._-]+\/|[A-Za-z]:\\Users\\[^\\\s]+|\/private\/tmp\/claude-/ },
  { id: 'email', value: (m) => m.toLowerCase(), ok: (m) => EMAIL_OK.test(m), re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g },
  { id: 'ip-address', value: (m) => m, ok: (m) => IP_OK.test(m), re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
]

/** The fingerprint an allow entry names: sha256 of the value, hex. */
export const fingerprint = (value) => createHash('sha256').update(value).digest('hex')

const mask = (s) => (s.length <= 8 ? '*'.repeat(s.length) : `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`)

/**
 * Findings in one line of text: [{ rule, match, sha256? }]. A finding about a
 * value (a key, a token, an address) carries the value's fingerprint; a
 * finding about a shape (a PEM header, a path) does not, and is allowed only
 * by the line marker or an ignored path.
 */
export function scanLine(line) {
  if (line.includes(ALLOW_MARKER)) return []
  const found = []
  const add = (rule, match) => {
    if (rule.ok && rule.ok(match)) return
    const value = rule.value ? rule.value(match) : undefined
    if (value !== undefined && PUBLIC_TEST_VALUES.has(value)) return
    found.push({ rule: rule.id, match, ...(value !== undefined ? { sha256: fingerprint(value) } : {}) })
  }
  for (const rule of RULES) {
    if (rule.re.global) {
      for (const m of line.matchAll(rule.re)) add(rule, m[0])
    } else {
      const m = line.match(rule.re)
      if (m) add(rule, m[0])
    }
  }
  return found
}

function globToRegExp(glob) {
  if (glob.endsWith('/')) return new RegExp('^' + glob.replace(/[.+^${}()|[\]\\]/g, '\\$&'))
  let re = ''
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]
    if (ch === '*' && glob[i + 1] === '*') {
      re += '.*'
      i++
      if (glob[i + 1] === '/') i++
    } else if (ch === '*') re += '[^/]*'
    else if (ch === '?') re += '[^/]'
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp('^' + re + '$')
}

/** The repository's exceptions (.privacy-check.json), or none. */
export function loadConfig(root) {
  const path = join(root, CONFIG_FILE)
  if (!existsSync(path)) return { ignore: [], allow: new Set() }
  const c = JSON.parse(readFileSync(path, 'utf8'))
  return {
    ignore: (c.ignorePaths || []).map(globToRegExp),
    allow: new Set((c.allow || []).map((a) => String(a.sha256).toLowerCase())),
  }
}

const git = (args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })

/** The lines a staged commit adds, as [{ file, line, text }], plus added file names. */
function stagedChanges() {
  const files = git(['diff', '--cached', '--name-only', '--diff-filter=ACR', '-z']).split('\0').filter(Boolean)
  const lines = []
  let file = null
  let lineNo = 0
  for (const row of git(['diff', '--cached', '--no-color', '--no-ext-diff', '-U0', '--diff-filter=ACMR']).split('\n')) {
    if (row.startsWith('+++ ')) {
      file = row.startsWith('+++ b/') ? row.slice(6) : null
      continue
    }
    const hunk = row.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
    if (hunk) { lineNo = Number(hunk[1]); continue }
    if (file && row.startsWith('+')) {
      lines.push({ file, line: lineNo, text: row.slice(1) })
      lineNo++
    }
  }
  return { files, lines }
}

/** Every line of every tracked file. */
function trackedContent() {
  const files = git(['ls-files', '-z']).split('\0').filter(Boolean)
  const lines = []
  for (const file of files) {
    if (SKIP_FILES.test(file)) continue
    let text
    try {
      if (statSync(file).size > 2 * 1024 * 1024) continue
      text = readFileSync(file, 'utf8')
    } catch { continue }
    if (text.includes('\u0000')) continue // binary
    text.split('\n').forEach((t, i) => lines.push({ file, line: i + 1, text: t }))
  }
  return { files, lines }
}

export function check({ files, lines }, config = { ignore: [], allow: new Set() }) {
  const ignored = (f) => SKIP_FILES.test(f) || config.ignore.some((re) => re.test(f))
  const findings = []
  for (const f of files) {
    if (SECRET_FILE.test(f) && !config.ignore.some((re) => re.test(f))) findings.push({ file: f, line: 0, rule: 'secret-file', match: f.split('/').pop() })
  }
  for (const { file, line, text } of lines) {
    if (ignored(file)) continue
    for (const hit of scanLine(text)) {
      if (hit.sha256 && config.allow.has(hit.sha256)) continue
      findings.push({ file, line, ...hit })
    }
  }
  return findings
}

function main(argv) {
  const root = git(['rev-parse', '--show-toplevel']).trim()
  process.chdir(root)
  const all = argv.includes('--all')
  const findings = check(all ? trackedContent() : stagedChanges(), loadConfig(root))
  if (!findings.length) return 0
  console.error(`privacy-check: ${findings.length} finding(s) — this repository is public:\n`)
  for (const f of findings) {
    const where = f.line ? `${f.file}:${f.line}` : f.file
    const shown = f.rule === 'secret-file' ? f.match : mask(f.match)
    console.error(`  ${where}  [${f.rule}]  ${shown}${f.sha256 ? `  sha256:${f.sha256}` : ''}`)
  }
  console.error(
    `\nRemove them${all ? '' : ' from the commit'}. If one is a genuine fixture, not private:` +
    `\n  - in code, end its line with "${ALLOW_MARKER}";` +
    `\n  - otherwise add its sha256 to "allow" in ${CONFIG_FILE}, with a note saying why.`,
  )
  return 1
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  process.exit(main(process.argv.slice(2)))
}
