/**
 * The layered runtime's owner surface (sealed/LAYERS.md §3, §10), no network:
 *
 * - the settings document's `versions` serializes as Go's settings.Versions
 *   (field order, omitempty, an empty pick dropped) and a malformed pick is
 *   refused before anything is signed;
 * - the CLI grammar: sealed=/harness= take a sha256 hash, merge into
 *   `versions`, clear with an empty value, render as their own keys, and are
 *   refused for an agent known to run another framework;
 * - the listed-versions rendering marks the newest, the pick, and a pick no
 *   longer listed;
 * - restartRuntime signs `0GSealRestart:<sealId>:<ts>:<sha256(body)>:<audience>`
 *   over the body {"layer": …}, sends the window's instance, and keeps the
 *   container's status in its error;
 * - listedVersions reads the trust registry's sealed and harness lists, and
 *   is null on a chain without one.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { ExecutionRevertedError, recoverMessageAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { AttestorClient, canonicalSettings, versionPicksProblem } from '../dist/index.js';
import { AgentApi } from '../dist/AgenticID.js';
import { TRUST_KINDS } from '../dist/TrustRegistry.js';
import {
  applyAssignments,
  assertVersionsFitFramework,
  parseAssignments,
  renderListedVersions,
  renderSettings,
} from '../dist/cli/settings.js';

const ACCOUNT = privateKeyToAccount(`0x${'42'.repeat(32)}`);
const SEAL = `0x${'7d'.repeat(32)}`;
const S1 = `0x${'a1'.repeat(32)}`;
const S2 = `0x${'a2'.repeat(32)}`;
const H1 = `0x${'b1'.repeat(32)}`;

// ── the document ──

test('canonicalSettings: versions after others, sealed before harness, empty picks dropped', () => {
  assert.equal(
    canonicalSettings({ versions: { harness: H1, sealed: S1 }, model: 'm', others: { a: 1 } }),
    `{"model":"m","others":{"a":1},"versions":{"sealed":"${S1}","harness":"${H1}"}}`,
  );
  assert.equal(canonicalSettings({ model: 'm', versions: { sealed: '', harness: undefined } }), '{"model":"m"}');
  assert.equal(canonicalSettings({ model: 'm', versions: {} }), '{"model":"m"}');
  assert.equal(canonicalSettings({ model: 'm', versions: { harness: H1 } }), `{"model":"m","versions":{"harness":"${H1}"}}`);
  // Not the container's shape: passed through for the container to refuse.
  assert.equal(canonicalSettings({ versions: 'latest' }), '{"versions":"latest"}');
});

test('canonicalSettings: a pick for a layer this SDK does not know is kept, after sealed and harness, in its own order', () => {
  const B1 = `0x${'c1'.repeat(32)}`;
  assert.equal(
    canonicalSettings({ model: 'm', versions: { zeta: 'z', harness: H1, base: B1, sealed: S1 } }),
    `{"model":"m","versions":{"sealed":"${S1}","harness":"${H1}","zeta":"z","base":"${B1}"}}`,
  );
  assert.equal(canonicalSettings({ model: 'm', versions: { base: B1 } }), `{"model":"m","versions":{"base":"${B1}"}}`);
  // The CLI's read-modify-write keeps it too, and shows it.
  const next = applyAssignments({ model: 'm', versions: { sealed: S1, base: B1 } }, parseAssignments(['sealed=']));
  assert.deepEqual(next.versions, { base: B1 });
  assert.deepEqual(renderSettings(next), ['model      m', `versions.base ${B1}`]);
});

test('versionPicksProblem: a pick is "0x" + 64 hex or empty', () => {
  assert.equal(versionPicksProblem(undefined), null);
  assert.equal(versionPicksProblem({ sealed: S1, harness: '' }), null);
  assert.match(versionPicksProblem({ sealed: '0x1234' }), /versions\.sealed must be a sha256 hash/);
  assert.match(versionPicksProblem({ harness: S1.slice(2) }), /versions\.harness must be/);
  assert.match(versionPicksProblem('latest'), /must be an object/);
});

test('setSettings: a malformed version pick is refused before signing', async () => {
  let posted = false;
  const server = createServer((req, res) => {
    if (req.method === 'POST') posted = true;
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"chain_id":16602,"version":1}');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const client = new AttestorClient({
    attestorUrl: `http://127.0.0.1:${server.address().port}`,
    account: ACCOUNT,
    walletClient: { signMessage: ({ message }) => ACCOUNT.signMessage({ message }) },
  });
  try {
    await assert.rejects(
      client.setSettings({ sealId: SEAL, settings: { model: 'm', versions: { sealed: '0x12' } }, baseVersion: 0 }),
      /setSettings: versions\.sealed must be a sha256 hash/,
    );
    assert.equal(posted, false, 'nothing was sent');
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

// ── the CLI grammar ──

test('sealed=/harness= merge into versions, clear with an empty value, and render as their own keys', () => {
  const base = { model: 'm', versions: { sealed: S1 } };
  const next = applyAssignments(base, parseAssignments([`harness=${H1}`]));
  assert.deepEqual(next.versions, { sealed: S1, harness: H1 });
  assert.deepEqual(base.versions, { sealed: S1 }, 'the stored document is not mutated');
  assert.deepEqual(renderSettings(next), ['model      m', `sealed     ${S1}`, `harness    ${H1}`]);

  const cleared = applyAssignments(next, parseAssignments(['sealed=', 'harness=']));
  assert.ok(!('versions' in cleared), 'no pick left → no versions section');
  assert.deepEqual(applyAssignments(next, parseAssignments([`sealed=${S2}`])).versions, { sealed: S2, harness: H1 });
});

test('sealed=/harness= take a sha256 hash only', () => {
  for (const arg of ['sealed=latest', 'harness=0x12', `sealed=${S1.slice(2)}`]) {
    assert.throws(() => parseAssignments([arg]), (e) => e.code === 'BAD_FLAG' && /takes a version's sha256 hash/.test(e.message), arg);
  }
  assert.throws(() => parseAssignments(['versions={}']), (e) => e.code === 'BAD_FLAG' && /unknown setting "versions"/.test(e.message));
});

test('version picks are refused for an agent known to run another framework', () => {
  const picks = parseAssignments([`sealed=${S1}`, 'model=x']);
  assert.throws(() => assertVersionsFitFramework(picks, 'openclaw'), (e) => e.code === 'BAD_FLAG' && /only 0g-harness agents have/.test(e.message));
  assertVersionsFitFramework(picks, '0g-harness');
  assertVersionsFitFramework(picks, 'dsh'); // the harness's earlier name
  assertVersionsFitFramework(picks, undefined); // a legacy row: not refused
  assertVersionsFitFramework(parseAssignments(['sealed=', 'model=x']), 'openclaw'); // clearing is fine anywhere
});

test('renderListedVersions marks the newest, the pick, and a pick no longer listed', () => {
  const lines = renderListedVersions({ sealed: [S1, S2], harness: [] }, { sealed: S1, harness: H1 });
  assert.deepEqual(lines.slice(1), [
    `  sealed   ${S1}  (picked)`,
    `  sealed   ${S2}  (newest)`,
    '  harness  (none listed)',
    `  harness  ${H1}  (picked, not listed: not run)`,
  ]);
});

// ── owner restart ──

test('restartRuntime: signed over the body digest, audience last, instance sent', async () => {
  let seen;
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen = { path: req.url, body, msg: req.headers['x-auth-message'], sig: req.headers['x-auth-signature'], instance: req.headers['x-client-instance'] };
      if (JSON.parse(body).layer === 'sealed') {
        res.writeHead(503, { 'content-type': 'text/plain' }).end('sealed is still starting');
        return;
      }
      res.writeHead(202, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, layer: 'harness', note: 'restarting the harness; the conversation and the disk stay' }));
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const stub = {
    ctx: { account: ACCOUNT, walletClient: { signMessage: ({ message }) => ACCOUNT.signMessage({ message }) } },
    id: { getSealId: async () => SEAL },
  };
  try {
    const out = await AgentApi.prototype.restartRuntime.call(stub, base, 1n, 'harness', 'window-A');
    assert.equal(out.note, 'restarting the harness; the conversation and the disk stay');
    assert.equal(seen.path, '/_seal/restart');
    assert.equal(seen.body, '{"layer":"harness"}');
    assert.equal(seen.instance, 'window-A');
    const parts = seen.msg.split(':');
    assert.equal(parts[0], '0GSealRestart');
    assert.equal(parts[1], SEAL);
    assert.equal(parts[3], createHash('sha256').update(seen.body, 'utf8').digest('hex'), 'body digest before the audience');
    assert.equal(parts.slice(4).join(':'), base, 'audience last and whole');
    assert.equal((await recoverMessageAddress({ message: seen.msg, signature: seen.sig })).toLowerCase(), ACCOUNT.address.toLowerCase());

    await assert.rejects(
      AgentApi.prototype.restartRuntime.call(stub, base, 1n, 'sealed'),
      /^Error: restartRuntime: HTTP 503: sealed is still starting/,
    );
    assert.equal(seen.instance, undefined, 'no instance header without one');
  } finally {
    srv.closeAllConnections?.();
    srv.close();
  }
});

// ── listed versions ──

test('listedVersions: the trust registry\'s sealed and harness lists; null without a registry', async () => {
  const TRUST = '0x0000000000000000000000000000000000007777';
  const lists = { [TRUST_KINDS.sealed]: [S1, S2], [TRUST_KINDS.harness]: [H1] };
  const api = (registry) => ({
    ctx: {
      addresses: { agenticID: '0x00000000000000000000000000000000000000A9' },
      publicClient: {
        readContract: async ({ functionName, address, args }) => {
          if (functionName === 'trustRegistry') {
            if (!registry) throw new ExecutionRevertedError({ message: 'execution reverted' });
            return registry;
          }
          if (functionName === 'listed' && address === TRUST) return lists[args[0]];
          throw new Error(`unstubbed read: ${functionName}`);
        },
      },
    },
  });
  assert.deepEqual(await AgentApi.prototype.listedVersions.call(api(TRUST)), { registry: TRUST, sealed: [S1, S2], harness: [H1] });
  assert.equal(await AgentApi.prototype.listedVersions.call(api(null)), null);
});
