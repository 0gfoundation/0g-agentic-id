import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress } from 'viem';
import { AgentDNA, AttestorClient, OPERATOR_DOMAIN, OperatorConflictError } from '../dist/index.js';

const OWNER = privateKeyToAccount(`0x${'11'.repeat(32)}`); // fixture: privacy-check: allow
const OPERATOR = privateKeyToAccount(`0x${'22'.repeat(32)}`); // fixture: privacy-check: allow
const OTHER = privateKeyToAccount(`0x${'33'.repeat(32)}`); // fixture: privacy-check: allow
const SEAL = `0x${'44'.repeat(32)}`;
const CONTRACT = '0x0000000000000000000000000000000000000055';
const PROVIDER = '0x0000000000000000000000000000000000000066';
const SEAL_ADDR = '0x0000000000000000000000000000000000000077';
const CHECKPOINT = { number: 123, hash: `0x${'cd'.repeat(32)}` };

async function server(t, initial = {}) {
  const state = {
    owner: OWNER.address, operator: OPERATOR.address, version: 4, allow_recreate: false,
    expires_at: 0, sandbox_id: null, sandbox_controller: null, checkpoint: CHECKPOINT, ...initial,
  };
  const puts = [], posts = [], signed = [], reads = [];
  let putStatus = 200;
  let getStatus = 200;
  let lifecycleStatus = 202;
  const http = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://fixture');
      if (req.method === 'GET') reads.push(url.pathname);
      const json = (code, value) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(value));
      };
      if (req.method === 'GET' && url.pathname === '/operator') return getStatus === 200
        ? json(200, state) : json(getStatus, { error: 'operator lookup unavailable' });
      if (req.method === 'PUT' && url.pathname === '/operator') {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        puts.push(body);
        if (putStatus !== 200) return json(putStatus, { error: 'operator version changed', version: state.version });
        const document = JSON.parse(Buffer.from(body.signed_message_b64, 'base64').toString());
        Object.assign(state, {
          operator: document.operator, version: state.version + 1, expires_at: document.expires_at,
          allow_recreate: document.allow_recreate, sandbox_id: null, sandbox_controller: null,
        });
        return json(200, state);
      }
      if (req.method === 'GET' && url.pathname.startsWith('/deployment/')) {
        return json(200, { seal_id: SEAL, framework: 'openclaw', sandbox_id: state.sandbox_id,
          provisioned_at: state.sandbox_id ? '2026-11-01T00:00:00Z' : null,
          // An owner start would seed settings; an operator must never do so.
          clone_params: { source_agent_id: '1' }, settings_version: state.settings_version ?? 0 });
      }
      if (req.method === 'GET' && url.pathname === '/config') return json(200, {
        sandbox_snapshot: 'sealed-image', sandbox_provider_addr: PROVIDER,
        secret_env_scheme: 'agent-seal-ecies-v1',
      });
      if (req.method === 'POST') {
        posts.push({ path: url.pathname, body: JSON.parse(Buffer.concat(chunks).toString()) });
        return lifecycleStatus === 202 ? json(202, { accepted: true })
          : json(lifecycleStatus, { code: 'NOT_RESUMABLE', error: 'current sandbox cannot resume; use reset explicitly' });
      }
      return json(404, { error: 'not found' });
    });
  });
  await new Promise((resolve) => http.listen(0, '127.0.0.1', resolve));
  t.after(() => http.close());
  const base = `http://127.0.0.1:${http.address().port}`;
  const ctx = (account) => ({
    attestorUrl: base, account, chain: { id: 16602 }, addresses: { agenticID: CONTRACT },
    walletClient: { signMessage: ({ message }) => { signed.push(message); return account.signMessage({ message }); } },
    publicClient: { readContract: async ({ functionName }) => {
      if (functionName === 'getAgentIdBySealId') return 42n;
      if (functionName === 'getAgentSeal') return SEAL_ADDR;
      if (functionName === 'ownerOf') return state.owner;
      throw new Error(`unexpected chain call ${functionName}`);
    } },
  });
  return { state, puts, posts, signed, reads, base, client: (account) => new AttestorClient(ctx(account)),
    failPut: (code) => { putStatus = code; }, failGet: (code) => { getStatus = code; },
    failLifecycle: (code) => { lifecycleStatus = code; } };
}

function envelope(post) {
  const env = post.body.sandbox_envelope;
  return { env, message: Buffer.from(env.signed_message_b64, 'base64').toString() };
}

test('owner appoints and revokes an operator with domain-separated CAS signatures', async (t) => {
  const f = await server(t, { sandbox_id: 'retired-runtime', sandbox_controller: OPERATOR.address });
  const expiry = Math.floor(Date.now() / 1000) + 3600;
  const updated = await f.client(OWNER).setOperator(SEAL, OTHER.address, { expiresAt: expiry, allowRecreate: true });
  const put = f.puts[0];
  const message = Buffer.from(put.signed_message_b64, 'base64').toString();
  const document = JSON.parse(message);
  assert.deepEqual(document, {
    domain: OPERATOR_DOMAIN, chain_id: 16602, contract: CONTRACT, seal_id: SEAL,
    owner: OWNER.address, base_version: 4, operator: OTHER.address, allow_recreate: true,
    expires_at: expiry, issued_at: document.issued_at, checkpoint: CHECKPOINT,
  });
  assert.equal(await recoverMessageAddress({ message, signature: put.signature }), OWNER.address);
  assert.equal(updated.operator, OTHER.address);
  assert.equal(updated.version, 5);
  assert.equal(f.state.sandbox_id, null);
  assert.equal(f.state.sandbox_controller, null);
  const revoked = await f.client(OWNER).revokeOperator(SEAL);
  const revoke = JSON.parse(Buffer.from(f.puts[1].signed_message_b64, 'base64').toString());
  assert.equal(revoke.base_version, 5);
  assert.equal(revoke.operator, null);
  assert.equal(revoke.allow_recreate, false);
  assert.equal(revoke.expires_at, 0);
  assert.deepEqual(revoke.checkpoint, CHECKPOINT);
  assert.equal(revoked.operator, null);
});

test('an operator cannot appoint itself; invalid grants and stale writes never silently retry', async (t) => {
  const f = await server(t);
  await assert.rejects(f.client(OPERATOR).setOperator(SEAL, OPERATOR.address), /current NFT owner/);
  await assert.rejects(f.client(OWNER).setOperator(SEAL, '0x0000000000000000000000000000000000000000'), /nonzero/);
  await assert.rejects(f.client(OWNER).setOperator(SEAL, OPERATOR.address, { expiresAt: -1 }), /future Unix/);
  assert.equal(f.signed.length, 0);
  f.failPut(409);
  await assert.rejects(f.client(OWNER).setOperator(SEAL, OPERATOR.address, { baseVersion: 1 }), OperatorConflictError);
  assert.equal(f.puts.length, 1);
  assert.equal(f.signed.length, 1);
});

test('grant writes require and sign the exact checkpoint supplied by the lookup', async (t) => {
  const f = await server(t, { checkpoint: null });
  const c = f.client(OWNER);
  assert.equal((await c.getOperator(SEAL)).checkpoint, null);
  await assert.rejects(c.setOperator(SEAL, OPERATOR.address), /ownership checkpoint/);
  assert.equal(f.signed.length, 0);
  assert.equal(f.puts.length, 0);
  const checkpoint = { number: 456, hash: `0x${'ef'.repeat(32)}` };
  f.state.checkpoint = checkpoint;
  await c.setOperator(SEAL, OPERATOR.address);
  const document = JSON.parse(Buffer.from(f.puts[0].signed_message_b64, 'base64').toString());
  assert.deepEqual(document.checkpoint, checkpoint);
});

test('unsafe checkpoint numbers and malformed block hashes are rejected before signing', async (t) => {
  const f = await server(t);
  const c = f.client(OWNER);
  for (const checkpoint of [
    { number: Number.MAX_SAFE_INTEGER + 1, hash: CHECKPOINT.hash },
    { number: -1, hash: CHECKPOINT.hash },
    { number: 1.5, hash: CHECKPOINT.hash },
    { number: 123, hash: '0x1234' },
  ]) {
    f.state.checkpoint = checkpoint;
    await assert.rejects(c.setOperator(SEAL, OPERATOR.address), /invalid authorization summary/);
  }
  assert.equal(f.signed.length, 0);
  assert.equal(f.puts.length, 0);
});

test('operator pays under its signature while boot authority stays bound to the NFT owner', async (t) => {
  const f = await server(t);
  await f.client(OPERATOR).lifecycle('start', { sealId: SEAL });
  const posted = f.posts[0];
  const { env, message } = envelope(posted);
  const canonical = JSON.parse(message);
  assert.equal(posted.body.owner, OWNER.address);
  assert.equal(env.wallet_address, OPERATOR.address);
  assert.equal(await recoverMessageAddress({ message, signature: env.wallet_signature }), OPERATOR.address);
  assert.equal(canonical.action, 'create');
  assert.equal(canonical.provider, PROVIDER);
  assert.deepEqual(canonical.agentic_id, { chain_id: 16602, contract: CONTRACT, seal_id: SEAL, operator_version: 4 });
  assert.equal(canonical.payload.agentic_id, undefined);
  assert.equal(canonical.payload.env, undefined);
  assert.deepEqual(f.posts.map((p) => p.path), ['/start']);
  assert.equal(f.signed.length, 1, 'no owner settings or credential signature');
});

test('operator lifecycle refuses owner configuration options before any write or signature', async (t) => {
  const f = await server(t);
  const c = f.client(OPERATOR);
  let ranOwnerWrite = false;
  for (const options of [
    { apiKey: 'fixture-model-key' },
    { sealedSecretEnv: 'fixture-sealed-key' },
    { provider: 'openai' },
    { beforeWrite: async () => { ranOwnerWrite = true; } },
  ]) {
    await assert.rejects(c.lifecycle('start', { sealId: SEAL, ...options }), /compute only/);
  }
  assert.equal(ranOwnerWrite, false);
  assert.equal(f.signed.length, 0);
  assert.equal(f.posts.length, 0);
});

test('operator lifecycle never runs the owner-only model planning callback', async (t) => {
  const f = await server(t);
  let planned = false;
  await f.client(OPERATOR).lifecycle('start', { sealId: SEAL, prepareModelKey: async () => {
    planned = true;
    throw new Error('owner callback must not run');
  } });
  assert.equal(planned, false);
  assert.deepEqual(f.posts.map((p) => p.path), ['/start']);
});

test('operator facade never reads or writes the owner credential set', async (t) => {
  const f = await server(t, { allow_recreate: true });
  const ag = new AgentDNA({ attestorUrl: f.base, account: OPERATOR, addresses: { agenticID: CONTRACT } });
  const readsOrWrites = [];
  ag.agent.credentials = {
    get: async () => { readsOrWrites.push('get'); throw new Error('owner only'); },
    setModelKey: async () => { readsOrWrites.push('setModelKey'); throw new Error('owner only'); },
  };
  await ag.agent.start(SEAL);
  await ag.agent.reset(SEAL);
  await assert.rejects(ag.agent.start(SEAL, { apiKey: 'fixture-model-key' }), /compute only/);
  await assert.rejects(ag.agent.reset(SEAL, { sealedModelKey: { provider: 'openai' } }), /compute only/);
  await assert.rejects(ag.agent.start(SEAL, { keepStoredModelKey: true }), /compute only/);
  assert.deepEqual(readsOrWrites, []);
  assert.deepEqual(f.posts.map((p) => p.path), ['/start', '/reset']);
  for (const post of f.posts) assert.equal(post.body.sandbox_envelope.wallet_address, OPERATOR.address);
});

test('owner pre-mint stop, reset and retry accept a non-delegated summary without a checkpoint', async (t) => {
  const f = await server(t, { operator: null, version: 0, checkpoint: null,
    sandbox_id: 'pre-mint-sandbox', settings_version: 1 });
  const ag = new AgentDNA({ attestorUrl: f.base, account: OWNER, addresses: { agenticID: CONTRACT } });
  await ag.agent.stop(SEAL);
  await ag.agent.reset(SEAL);
  await ag.agent.retry(SEAL);
  assert.deepEqual(f.posts.map((p) => p.path), ['/stop', '/reset', '/retry']);
  for (const post of f.posts.slice(0, 2)) {
    const { env, message } = envelope(post);
    assert.equal(env.wallet_address, OWNER.address);
    assert.equal(JSON.parse(message).agentic_id, undefined);
  }
});

test('owner compatibility only tolerates an absent operator endpoint, not arbitrary lookup errors', async (t) => {
  const f = await server(t, { operator: null, settings_version: 1 });
  const c = f.client(OWNER);
  for (const code of [400, 500]) {
    f.failGet(code);
    await assert.rejects(c.lifecycle('stop', { sealId: SEAL, sandboxId: 'sandbox' }), /operator failed/);
  }
  assert.equal(f.posts.length, 0);
  assert.equal(f.signed.length, 0);
  f.failGet(404);
  await c.lifecycle('stop', { sealId: SEAL, sandboxId: 'sandbox' });
  assert.equal(f.posts[0].path, '/stop');
});

test('each lifecycle call reads authority and deployment once, without caching across calls', async (t) => {
  for (const account of [OWNER, OPERATOR]) {
    for (const action of ['start', 'reset', 'stop']) {
      const f = await server(t, { sandbox_id: 'current-runtime', settings_version: 1 });
      const ag = new AgentDNA({ attestorUrl: f.base, account, addresses: { agenticID: CONTRACT } });
      await ag.agent[action](SEAL);
      assert.equal(f.reads.filter((p) => p === '/operator').length, 1, `${account.address} ${action}: one authority read`);
      assert.equal(f.reads.filter((p) => p.startsWith('/deployment/')).length, 1, `${action}: one deployment read`);
      await ag.agent[action](SEAL);
      assert.equal(f.reads.filter((p) => p === '/operator').length, 2, `${action}: re-read authority on next call`);
      assert.equal(f.reads.filter((p) => p.startsWith('/deployment/')).length, 2, `${action}: re-read deployment on next call`);
    }
  }
});

test('every operator request binds the current grant version; revoked and expired operators sign nothing', async (t) => {
  const f = await server(t);
  const c = f.client(OPERATOR);
  await c.lifecycle('start', { sealId: SEAL, sandboxId: 'sandbox-operated' });
  assert.equal(JSON.parse(envelope(f.posts[0]).message).agentic_id.operator_version, 4);
  f.state.version = 6;
  await c.lifecycle('stop', { sealId: SEAL, sandboxId: 'sandbox-operated' });
  assert.equal(JSON.parse(envelope(f.posts[1]).message).agentic_id.operator_version, 6);
  assert.deepEqual(JSON.parse(envelope(f.posts[1]).message).payload, {});
  f.state.operator = null;
  await assert.rejects(c.lifecycle('start', { sealId: SEAL, sandboxId: 'sandbox-operated' }), /active operator/);
  f.state.operator = OPERATOR.address;
  f.state.expires_at = Math.floor(Date.now() / 1000) - 1;
  await assert.rejects(c.lifecycle('start', { sealId: SEAL, sandboxId: 'sandbox-operated' }), /active operator/);
  assert.equal(f.signed.length, 2);
});

test('facade resolves an existing sandbox by seal for start and stop', async (t) => {
  const f = await server(t, { sandbox_id: 'current-runtime', sandbox_controller: OPERATOR.address });
  const ag = new AgentDNA({ attestorUrl: f.base, account: OPERATOR, addresses: { agenticID: CONTRACT } });
  await ag.agent.start(SEAL);
  await ag.agent.stop(SEAL);
  assert.equal(f.posts[0].path, '/start');
  assert.equal(f.posts[1].path, '/stop');
  for (const post of f.posts) {
    const request = JSON.parse(envelope(post).message);
    assert.equal(request.resource_id, 'current-runtime');
    assert.notEqual(request.action, 'create');
  }
});

test('a non-resumable sandbox never causes an implicit reset or new paid create', async (t) => {
  const f = await server(t, { sandbox_id: 'partial-runtime' });
  f.failLifecycle(409);
  const ag = new AgentDNA({ attestorUrl: f.base, account: OPERATOR, addresses: { agenticID: CONTRACT } });
  await assert.rejects(ag.agent.start(SEAL), /NOT_RESUMABLE/);
  assert.deepEqual(f.posts.map((p) => p.path), ['/start']);
  assert.equal(JSON.parse(envelope(f.posts[0]).message).action, 'start');
  assert.equal(f.posts[0].body.sandbox_envelope.wallet_address, OPERATOR.address);
});

test('mint-only deploy does not require the NFT owner to fund a sandbox', async () => {
  const ag = new AgentDNA({ account: OWNER, addresses: {
    agenticID: CONTRACT, tappRegistry: CONTRACT, sandboxServing: CONTRACT,
  } });
  ag.agent.infra.ackStatus = async () => ({ allAcked: true, missing: [] });
  ag.agent.preflightCanReceiveNfts = async () => {};
  ag.agent.attestor.getEffectiveBalance = async () => { throw new Error('mint-only must not check sandbox balance'); };
  ag.agent.infra.getBalance = async () => { throw new Error('mint-only must not check sandbox balance'); };
  ag.agent.attestor.deploy = async () => ({ seal_id: SEAL, agent_seal_addr: SEAL_ADDR });
  const result = await ag.agent.deploy({ name: 'operator hosted', description: 'mint first, operator provisions later' });
  assert.equal(result.sealId, SEAL);
});
