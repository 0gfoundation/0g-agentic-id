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
// to stdio servers, with the proxy's per-boot CA in NODE_EXTRA_CA_CERTS.
// Chromium trusts that CA by the fingerprint of its public key
// (--ignore-certificate-errors-spki-list), on top of the system roots; no
// other certificate error is ignored. Chromium's own process
// sandbox needs user namespaces the sandbox container does not grant, so it
// runs without it, inside the agent's container.
import { spawn } from 'node:child_process'
import { X509Certificate, createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

const CREDENTIAL_CA = process.env.NODE_EXTRA_CA_CERTS || '/etc/seal/credential-ca.pem'
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
  } catch (err) {
    // No credential CA this boot: hosts the proxy terminates fail TLS; the
    // rest are tunnelled with their own certificates and work.
    process.stderr.write(`sealed-browser-mcp: no credential CA (${CREDENTIAL_CA}: ${err.message}); hosts the credential proxy fills fail TLS\n`)
  }
}

// The configuration holds the proxy password, so it lives in a 0700 directory,
// removed when the server ends.
const dir = mkdtempSync(join(tmpdir(), 'sealed-browser-'))
const cleanup = () => rmSync(dir, { recursive: true, force: true })
const config = join(dir, 'config.json')
writeFileSync(config, JSON.stringify({
  browser: { browserName: 'chromium', isolated: true, launchOptions },
  outputDir: join(homedir(), 'browser-output'),
}), { mode: 0o600 })

const child = spawn('playwright-mcp', ['--config', config, ...process.argv.slice(2)], { stdio: 'inherit' })
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal))
child.on('error', (err) => {
  cleanup()
  process.stderr.write(`sealed-browser-mcp: cannot start playwright-mcp: ${err.message}\n`)
  process.exit(1)
})
child.on('exit', (code, signal) => {
  cleanup()
  process.exit(code ?? (signal ? 1 : 0))
})
