import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadCredentials, saveApiKey, loadApiKey, inferenceKeyFromEnv, configPaths } from '../dist/cli/config.js';
import { configuredInferenceKey, agentInferenceProvider, resetInferenceProvider, requireConfiguredInferenceKey, deployWithInference } from '../dist/cli/inference.js';
import { listInferenceProviders } from '../dist/Providers.js';
import { completeLine } from '../dist/cli/commands/interactive.js';

const KEY = `0x${'42'.repeat(32)}`;
const fresh = () => ({ XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'agentdna-providers-')) });

test('deploy wizard binds changed compute routes after mint and keeps legacy compute deployment',async()=>{
  const seal=`0x${'5e'.repeat(32)}`;
  for (const kind of ['builtin','changed-compute','partner','changed-mint-only']) {
    const providers=listInferenceProviders();
    const selected=structuredClone(providers[0]);
    delete selected.modelCatalog;
    selected.models=[{id:'model',supported_formats:['openai']}];
    if (kind!=='builtin') selected.endpoints.openai='https://partner.example/v1';
    if (kind==='partner') selected.id='partner';
    const calls=[];
    const provision=kind!=='changed-mint-only';
    const ag={agent:{
      refreshProviders:async()=>[selected],
      assertProviderSupported:async()=>{},
      deploy:async(params)=>{calls.push(['deploy',params]);return {sealId:seal};},
      waitForMint:async()=>{calls.push(['mint']);return {agentId:42n};},
      setSettings:async(...args)=>{calls.push(['settings',...args]);return {version:1};},
      start:async(...args)=>{calls.push(['start',...args]);},
    }};
    const result=await deployWithInference(ag,{name:'test',framework:'openclaw',provider:selected.id,model:'model',provision,...(provision?{apiKey:'test-private-key'}:{})});
    assert.equal(result.agentId,'42');
    if (kind==='builtin') {
      assert.deepEqual(calls.map(c=>c[0]),['deploy','mint']);
      assert.equal(calls[0][1].sandbox.apiKey,'test-private-key');
    } else {
      assert.deepEqual(calls.map(c=>c[0]),provision?['deploy','mint','settings','start']:['deploy','mint','settings']);
      assert.equal(calls[0][1].sandbox,undefined);
      assert.ok(!JSON.stringify(calls[0][1]).includes('test-private-key'));
      assert.deepEqual(calls[2].slice(1),[seal,{provider:selected.id,model:'model'},{baseVersion:0}]);
      if (provision) assert.deepEqual(calls[3].slice(1),[seal,{provider:selected.id,framework:'openclaw',apiKey:'test-private-key',secretEnv:'sealed'}]);
    }
  }
});

test('legacy compute key migrates atomically and registering another provider preserves both keys and owner', () => {
  const env = fresh();
  const { dir, credentials } = configPaths(env);
  mkdirSync(dir);
  writeFileSync(credentials, JSON.stringify({ privateKey:KEY,apiKey:'sk-old-compute' }), { mode:0o600 });
  assert.deepEqual(loadCredentials(env), { privateKey:KEY,inferenceKeys:{ '0g-compute':'sk-old-compute' } });
  saveApiKey('openai','sk-openai',env);
  saveApiKey('anthropic','sk-anthropic',env);
  assert.equal(loadApiKey('0g-compute',env), 'sk-old-compute');
  assert.equal(loadApiKey('openai',env), 'sk-openai');
  assert.deepEqual(JSON.parse(readFileSync(credentials,'utf8')), { privateKey:KEY,inferenceKeys:{ '0g-compute':'sk-old-compute',openai:'sk-openai',anthropic:'sk-anthropic' } });
  assert.equal(statSync(credentials).mode & 0o777,0o600);
});

test('legacy environment keys cannot cross provider boundaries', () => {
  const env = { ...fresh(),AGENTIC_API_KEY:'sk-compute' };
  assert.equal(inferenceKeyFromEnv('openai',env), null);
  assert.equal(configuredInferenceKey('openai',env), null);
  assert.throws(() => requireConfiguredInferenceKey('openai',env), (error) => error.code === 'INFERENCE_KEY_REQUIRED');
  assert.equal(inferenceKeyFromEnv('0g-compute',env),'sk-compute');
  const scoped = { ...env,AGENTDNA_API_KEY:'sk-openai',AGENTDNA_API_KEY_PROVIDER:'openai' };
  assert.equal(inferenceKeyFromEnv('openai',scoped),'sk-openai');
  assert.equal(inferenceKeyFromEnv('0g-compute',scoped),'sk-compute');
  assert.throws(() => inferenceKeyFromEnv('openai',{ AGENTDNA_API_KEY:'unbound' }),/AGENTDNA_API_KEY_PROVIDER/);
});

test('reset takes the provider from the agent settings and never hides a failed read', async () => {
  const seal = `0x${'11'.repeat(32)}`;
  assert.equal(await agentInferenceProvider({ agent:{ getSettings:async()=>({ settings:{ provider:'anthropic' } }) } },seal),'anthropic');
  assert.equal(await agentInferenceProvider({ agent:{ getSettings:async()=>({ settings:null }) } },seal),'0g-compute');
  await assert.rejects(agentInferenceProvider({ agent:{ getSettings:async()=>{ throw new Error('unreadable'); } } },seal),/unreadable/);
});

test('reset gives an agent with no settings the default model pin first', async () => {
  const seal = `0x${'11'.repeat(32)}`;
  const writes = [];
  const notes = [];
  const agent = (stored) => ({ agent:{
    getSettings:async()=>stored,
    setSettings:async(sealId,doc,opts)=>{ writes.push({ sealId, doc, opts }); return { version:1 }; },
  } });
  // A clone whose new owner has written nothing: the default is stored first.
  assert.equal(await resetInferenceProvider(agent({ settings:null, version:0 }),seal,(l)=>notes.push(l)),'0g-compute');
  assert.deepEqual(writes,[{ sealId:seal, doc:{ provider:'0g-compute', model:'0gm-1.0-35b-a3b' }, opts:{ baseVersion:0 } }]);
  assert.match(notes[0],/no settings yet/);
  // An agent that has settings keeps them.
  assert.equal(await resetInferenceProvider(agent({ settings:{ provider:'anthropic', model:'m' }, version:4 }),seal,(l)=>notes.push(l)),'anthropic');
  assert.equal(writes.length,1);
  await assert.rejects(resetInferenceProvider({ agent:{ getSettings:async()=>{ throw new Error('unreadable'); } } },seal,()=>{}),/unreadable/);
});

test('inline provider model completion cannot reuse compute suggestions', () => {
  const state = { completions:['/settings'],args:{},models:['compute-model'],providerModels:{ openai:['private-model'] } };
  assert.deepEqual(completeLine('/settings provider=openai model=',state)[0],['model=private-model']);
  assert.deepEqual(completeLine('/settings provider=anthropic model=',state)[0],['model=']);
});

test('login registers a provider key without exposing it or replacing the compute key', async () => {
  const env = fresh();
  const old = join(env.XDG_CONFIG_HOME,'0g-agenticid');
  mkdirSync(old);
  writeFileSync(join(old,'credentials'),JSON.stringify({ privateKey:KEY,apiKey:'sk-old-compute' }),{ mode:0o600 });
  const result = await new Promise((resolve,reject) => {
    const child = spawn(process.execPath,[new URL('../dist/cli/main.js',import.meta.url).pathname],{ env:{ PATH:process.env.PATH,...env } });
    let stdout='',stderr='';
    child.stdout.on('data',(data)=>stdout+=data);
    child.stderr.on('data',(data)=>stderr+=data);
    child.on('error',reject);
    child.on('close',(code)=>resolve({ code,stdout,stderr }));
    child.stdin.end('login openai\n\n\nsk-private-openai\nwhoami\nquit\n');
  });
  assert.equal(result.code,0,result.stderr);
  assert.equal(loadApiKey('openai',env),'sk-private-openai');
  assert.equal(loadApiKey('0g-compute',env),'sk-old-compute');
  assert.ok(!result.stdout.includes('sk-private-openai') && !result.stderr.includes('sk-private-openai'));
  assert.ok(!result.stdout.includes(KEY) && !result.stderr.includes(KEY));
  assert.match(result.stdout,/key openai: set/);
});
