#!/usr/bin/env node
// sealed-browser-mcp: the 0g-harness image's browser for the owner's agent, a
// DSH stdio MCP server. The owner turns it on in the agent's settings:
//   others.mcpServers: [{"serverName":"browser","transport":"stdio","command":"sealed-browser-mcp"}]
// It runs the image's Playwright MCP server on the image's Chromium, headless.
//
// The browser's traffic goes through sealed's credential proxy, so a
// [[credential:<name>]] placeholder typed into a page is filled for the hosts
// and positions the owner allowed, as for the agent's other requests. The
// proxy's address and per-boot password come from HTTPS_PROXY, which DSH passes
// to stdio servers. Chromium trusts the proxy's per-boot CA by the fingerprint
// of its public key (--ignore-certificate-errors-spki-list), on top of the
// system roots; no other certificate error is ignored. Chromium's own process
// sandbox needs user namespaces the sandbox container does not grant, so it
// runs without it, inside the agent's container.
import { spawn } from 'node:child_process'
import { X509Certificate, createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

const CREDENTIAL_CA = '/etc/seal/credential-ca.pem'
const args = ['--disable-dev-shm-usage']
const launchOptions = { executablePath: '/usr/bin/chromium', headless: true, chromiumSandbox: false, args }

const proxy = process.env.HTTPS_PROXY || process.env.https_proxy
if (proxy) {
  const u = new URL(proxy)
  launchOptions.proxy = {
    server: `${u.protocol}//${u.host}`,
    username: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    bypass: process.env.NO_PROXY || process.env.no_proxy || '',
  }
  try {
    const spki = new X509Certificate(readFileSync(CREDENTIAL_CA)).publicKey.export({ type: 'spki', format: 'der' })
    args.push('--ignore-certificate-errors-spki-list=' + createHash('sha256').update(spki).digest('base64'))
  } catch {
    // No credential CA this boot: hosts the proxy terminates fail TLS; the
    // rest are tunnelled with their own certificates and work.
  }
}

// The configuration holds the proxy password, so it lives in a 0700 directory.
const dir = mkdtempSync(join(tmpdir(), 'sealed-browser-'))
const config = join(dir, 'config.json')
writeFileSync(config, JSON.stringify({
  browser: { browserName: 'chromium', isolated: true, launchOptions },
  outputDir: join(homedir(), 'browser-output'),
}), { mode: 0o600 })

const child = spawn('playwright-mcp', ['--config', config, ...process.argv.slice(2)], { stdio: 'inherit' })
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal))
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)))
