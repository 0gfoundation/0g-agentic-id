import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress, encodeFunctionResult } from 'viem';
import { tappRegistryAbi } from '../dist/abi.js';
import { ProviderRegistryClient, listInferenceProviders, registrySigningMessage, routeHash, acceptedRegistryDigest } from '../dist/Providers.js';
import { AgentDNA, AttestorClient } from '../dist/index.js';
import { loadApiKey } from '../dist/cli/config.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { gcm } from '@noble/ciphers/aes';

const KEY=`0x${'42'.repeat(32)}`;
const operator=privateKeyToAccount(KEY);
const fixture=JSON.parse(readFileSync(new URL('../../../sealed/internal/inference/testdata/registry-v1.json',import.meta.url),'utf8'));
const partner=fixture.snapshot.providers.at(-1);
const SEAL=`0x${'5e'.repeat(32)}`;
const PUB='0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ADDR='0x2c7536E3605D9C16a7a3D7b1898e529396a65c23';
const PRIV='4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';

function openSecretEnv(encoded) {
  const raw=Buffer.from(encoded,'base64'), eph=raw.subarray(0,65), nonce=raw.subarray(65,81), tag=raw.subarray(81,97);
  const shared=secp256k1.getSharedSecret(PRIV,eph,false);
  const key=hkdf(sha256,Buffer.concat([eph,shared]),undefined,undefined,32);
  return JSON.parse(Buffer.from(gcm(key,nonce).decrypt(Buffer.concat([raw.subarray(97),tag]))).toString());
}

async function server() {
  let snapshot={version:0,providers:listInferenceProviders()};
  let failureStatus=0, posted=null, writes=0, configReads=0;
  const configOverrides=new Map();
  const s=createServer(async(req,res)=>{
    const parts=[]; for await (const chunk of req) parts.push(chunk);
    const json=(value,status=200)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(value));};
    if(req.url==='/config') {
      const override=configOverrides.get(++configReads);
      if(typeof override==='number') return json({},override);
      return json({chain_id:fixture.chain_id,agentic_id_addr:fixture.agentic_id_addr,
      chain_rpc:`http://127.0.0.1:${s.address().port}/rpc`,provider_registry_schema:1,
      provider_registry_version:snapshot.version,provider_registry_digest:snapshot.version?acceptedRegistryDigest(snapshot.document,snapshot.signature):undefined,
      attestor_app_id:'attestor-test',tapp_registry_addr:`0x${'22'.repeat(20)}`,
      sandbox_snapshot:'dynamic-image',secret_env_scheme:'agent-seal-ecies-v1',
      inference_capabilities:[{image:'dynamic-image',providers:['0g-compute','openai','anthropic'],formats:['openai','anthropic'],secret_env_versions:[1,2,3]}],...override});
    }
    if(req.url==='/rpc') {
      const request=JSON.parse(Buffer.concat(parts).toString());
      const result=encodeFunctionResult({abi:tappRegistryAbi,functionName:'getAppInfo',result:{composeHash:'0x',volumesHash:'0x',imageHashes:[],owner:operator.address,registeredAt:1n}});
      const one=(rpc)=>({jsonrpc:'2.0',id:rpc.id,result:rpc.method==='eth_chainId'?'0x40da':result});
      return json(Array.isArray(request)?request.map(one):one(request));
    }
    if(req.url==='/inference/providers') return json(snapshot,failureStatus||200);
    if(req.url==='/admin/inference/providers' && req.method==='PUT') {
      const update=JSON.parse(Buffer.concat(parts).toString()), doc=JSON.parse(update.document);
      const signer=await recoverMessageAddress({message:registrySigningMessage(update.document),signature:update.signature});
      if(signer.toLowerCase()!==operator.address.toLowerCase()) return json({},403);
      if(doc.base_version!==snapshot.version) return json({version:snapshot.version},409);
      assert.equal(doc.chain_id,fixture.chain_id); assert.equal(doc.agentic_id_addr.toLowerCase(),fixture.agentic_id_addr);
      snapshot={version:snapshot.version+1,providers:doc.providers,...update}; writes++;
      return json({ok:true,version:snapshot.version});
    }
    if(req.url.startsWith('/deployment/')) return json({framework:'openclaw',phase:'running'});
    if(req.url.startsWith('/agent-seal-pubkey')) return json({seal_id:SEAL,agent_seal_pubkey:PUB,agent_seal_addr:SEAL_ADDR});
    if(req.url==='/reset') { posted=JSON.parse(Buffer.concat(parts).toString()); return json({}); }
    return json({},404);
  });
  await new Promise(resolve=>s.listen(0,'127.0.0.1',resolve));
  return {base:`http://127.0.0.1:${s.address().port}`,set:(value)=>snapshot=value,fail:(status=503)=>failureStatus=status,posted:()=>posted,writes:()=>writes,
    configAt:(n,value)=>configOverrides.set(n,value),configReads:()=>configReads,
    close:()=>{s.closeAllConnections?.();s.close();}};
}

function cli(base,args,input,env={}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[new URL('../dist/cli/main.js',import.meta.url).pathname,...args],{
      env:{PATH:process.env.PATH,XDG_CONFIG_HOME:mkdtempSync(join(tmpdir(),'provider-cli-')),AGENTIC_ATTESTOR_URL:base,AGENTIC_PRIVATE_KEY:KEY,...env}});
    let stdout='',stderr=''; child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);
    child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));child.stdin.end(input);
  });
}

function staticModels() {
  return [...listInferenceProviders().map(p=>{ if(p.id==='0g-compute') { delete p.modelCatalog; p.models=[{id:'compute-m',supported_parameters:['tools']}]; } return p; }),structuredClone(partner)];
}

test('shared fixture proves operator signature, route hash, and encrypted v3 content',async()=>{
  assert.equal(await recoverMessageAddress({message:registrySigningMessage(fixture.snapshot.document),signature:fixture.snapshot.signature}),fixture.admin);
  assert.equal(routeHash(partner),fixture.route_hash);
  assert.deepEqual(openSecretEnv(fixture.secret_env_v3),{v:3,owner:'0x00000000000000000000000000000000000000AA',provider:'partner',route_hash:fixture.route_hash,registry:{version:1,digest:fixture.config.provider_registry_digest},env:{API_KEY:'test-partner-key'}});
});

test('SDK publishes and refreshes a new provider without changing built-in definitions',async()=>{
  const s=await server();try {
    const ag=await AgentDNA.fromAttestor(s.base,{account:KEY});
    assert.equal(ag.agent.updateProviders,undefined,'platform administration must not be an agent operation');
    assert.equal((await ag.agent.getProviderRegistry()).version,0);
    await ag.admin.updateProviders(staticModels(),{baseVersion:0});
    assert.ok((await ag.agent.refreshProviders()).some(p=>p.id==='partner'));
    assert.deepEqual(await ag.agent.listModels({provider:'partner'}),['private-model']);
    assert.equal(listInferenceProviders().some(p=>p.id==='partner'),false);
    assert.equal((await ag.agent.getProviderRegistry()).version,1);
    await assert.rejects(ag.admin.updateProviders(staticModels(),{baseVersion:0}),/HTTP 409/);
  } finally {s.close();}
});

test('registry refuses tampering, rollback, invalid acceptance digests, and fetch failure',async()=>{
  const s=await server();try {
    const registry=new ProviderRegistryClient(s.base);
    const trust={chainId:fixture.chain_id,contract:fixture.agentic_id_addr,version:1,digest:fixture.config.provider_registry_digest};
    s.set(structuredClone(fixture.snapshot));await registry.refresh(trust);
    const bad=structuredClone(fixture.snapshot);bad.providers.at(-1).endpoints.openai='https://wrong.example/v1';
    s.set(bad);await assert.rejects(registry.refresh(trust),/content mismatch/);
    s.set({version:0,providers:listInferenceProviders()});await assert.rejects(registry.refresh(trust),/rolled-back/);
    s.set(fixture.snapshot);await assert.rejects(registry.refresh({...trust,digest:'0xwrong'}),/acceptance digest/);
    s.fail();await assert.rejects(registry.refresh(trust),/HTTP 503/);
    assert.equal(registry.list().at(-1).endpoints.openai,partner.endpoints.openai);
  } finally {s.close();}
});

test('an advertised registry returning 404 never falls back or reaches credential sealing',async()=>{
  const s=await server();try {
    for (const snapshot of [{version:0,providers:listInferenceProviders()},fixture.snapshot]) {
      s.set(snapshot);s.fail(404);
      // Each CLI invocation starts with a new registry client, so exercise the
      // first read, including when the server still advertises seed version 0.
      await assert.rejects(AgentDNA.fromAttestor(s.base),/HTTP 404/);
      const registry=new ProviderRegistryClient(s.base);
      await assert.rejects(registry.refresh({version:snapshot.version}),/HTTP 404/);
    }
    let sealed=false,signed=false;
    const c=new AttestorClient({attestorUrl:s.base,account:operator,walletClient:{signMessage:async()=>{signed=true;throw new Error('must not sign');}}});
    c.agentSealPubkey=async()=>{sealed=true;throw new Error('must not seal');};
    c.signEnvelope=async()=>{signed=true;throw new Error('must not sign');};
    await assert.rejects(c.lifecycle('reset',{sealId:SEAL,provider:'openai',apiKey:'test-key'}),/HTTP 404/);
    // Exercise key construction directly as well, before the lifecycle wallet gate.
    await assert.rejects(c.keyEnv('test-key',undefined,'auto',SEAL,'openai','dynamic-image'),/HTTP 404/);
    assert.equal(sealed,false);assert.equal(signed,false);
  } finally {s.close();}
});

test('a new provider resets with its route hash and only encrypted credentials',async()=>{
  const s=await server();try {
    const ag=await AgentDNA.fromAttestor(s.base,{account:KEY});await ag.admin.updateProviders(staticModels(),{baseVersion:0});
    const signed=[];
    const c=new AttestorClient({attestorUrl:s.base,account:operator,chain:{id:fixture.chain_id},addresses:{agenticID:fixture.agentic_id_addr},
      walletClient:{signMessage:async({message})=>{signed.push(message);return operator.signMessage({message});}},
      publicClient:{readContract:async({functionName})=>functionName==='getAgentIdBySealId'?1n:functionName==='getAgentSeal'?SEAL_ADDR:operator.address}});
    await c.lifecycle('reset',{sealId:SEAL,provider:'partner',apiKey:'secret-partner'});
    assert.equal(signed.length,1);assert.ok(!signed[0].includes('secret-partner'));
    const message=JSON.parse(Buffer.from(s.posted().sandbox_envelope.signed_message_b64,'base64').toString());
    const payload=openSecretEnv(message.payload.env.SEAL_SECRET_ENV);
    assert.equal(payload.v,3);assert.equal(payload.provider,'partner');assert.equal(payload.route_hash,routeHash(partner));
    assert.deepEqual(payload.registry,{version:1,digest:acceptedRegistryDigest((await ag.agent.getProviderRegistry()).document,(await ag.agent.getProviderRegistry()).signature)});
    assert.equal(payload.env.API_KEY,'secret-partner');assert.ok(!message.payload.env.API_KEY);
  } finally {s.close();}
});

test('CLI only reads providers and logs in; publication stays in the SDK/API',async()=>{
  const s=await server();const dir=mkdtempSync(join(tmpdir(),'providers-publish-'));try {
    const file=join(dir,'providers.json');
    const misplaced=await cli(s.base,['providers','update',file,'--json']);
    assert.equal(misplaced.code,2);assert.equal(s.writes(),0);
    const removed=await cli(s.base,['admin','providers','update',file,'--json']);
    assert.notEqual(removed.code,0);assert.equal(s.writes(),0);
    const help=await cli(s.base,['--help']);
    assert.doesNotMatch(help.stdout,/providers update|Operator-only: upload/);
    const ag=await AgentDNA.fromAttestor(s.base,{account:KEY});
    await ag.admin.updateProviders(staticModels(),{baseVersion:0});
    const listed=await cli(s.base,['providers','--json'],undefined,{AGENTIC_PRIVATE_KEY:''});
    assert.equal(listed.code,0,listed.stdout+listed.stderr);assert.equal(JSON.parse(listed.stdout).data.providers.at(-1).id,'partner');
    const env={XDG_CONFIG_HOME:join(dir,'config')};
    const login=await cli(s.base,[],'login partner\n\n\nnew-partner-key\nwhoami\nquit\n',env);
    assert.equal(login.code,0,login.stdout+login.stderr);assert.equal(loadApiKey('partner',env),'new-partner-key');
    assert.ok(!login.stdout.includes('new-partner-key')&&!login.stderr.includes('new-partner-key'));
    assert.equal(s.writes(),1,'only the SDK call may publish');
  } finally {s.close();}
});

test('encrypted credentials pin the old publication while a later reset authorizes the new one',async()=>{
  const s=await server();try {
    const ag=await AgentDNA.fromAttestor(s.base,{account:KEY});
    await ag.admin.updateProviders(staticModels(),{baseVersion:0});
    const c=new AttestorClient({attestorUrl:s.base,account:operator,chain:{id:fixture.chain_id},addresses:{agenticID:fixture.agentic_id_addr},
      walletClient:{signMessage:async({message})=>operator.signMessage({message})},
      publicClient:{readContract:async({functionName})=>functionName==='getAgentIdBySealId'?1n:functionName==='getAgentSeal'?SEAL_ADDR:operator.address}});
    const sealed=await c.sealApiKey({sealId:SEAL,owner:operator.address,provider:'partner',apiKey:'private-old-key'});
    const old=openSecretEnv(sealed);
    const next=staticModels();next.find(p=>p.id==='partner').endpoints.openai='https://next.example/v1';
    await ag.admin.updateProviders(next,{baseVersion:1});
    // An already signed envelope cannot be rebound by later discovery.
    assert.equal(openSecretEnv(sealed).registry.version,1);
    await c.lifecycle('reset',{sealId:SEAL,provider:'partner',apiKey:'private-new-key'});
    const envelope=JSON.parse(Buffer.from(s.posted().sandbox_envelope.signed_message_b64,'base64').toString());
    const current=openSecretEnv(envelope.payload.env.SEAL_SECRET_ENV);
    assert.equal(current.registry.version,2);
    assert.notEqual(current.registry.digest,old.registry.digest);
    assert.notEqual(current.route_hash,old.route_hash);
    assert.equal(current.route_hash,routeHash(next.find(p=>p.id==='partner')));
  } finally {s.close();}
});


test('factory discovery pins provider support before its second config read',async()=>{
  for (const override of [503,{provider_registry_schema:undefined}]) {
    const s=await server();try {
      s.configAt(2,override);
      await assert.rejects(AgentDNA.fromAttestor(s.base),override===503?/cannot read GET \/config/:/capability was withdrawn/);
    } finally {s.close();}
  }
});

test('a transient config failure refuses sealing even when the next read would recover',async()=>{
  const s=await server();try {
    await AgentDNA.fromAttestor(s.base);
    s.configAt(s.configReads()+1,503);
    const c=new AttestorClient({attestorUrl:s.base,account:operator});
    let sealed=false,signed=false;
    c.agentSealPubkey=async()=>{sealed=true;throw new Error('must not seal');};
    c.signEnvelope=async()=>{signed=true;throw new Error('must not sign');};
    await assert.rejects(c.keyEnv('secret-key',undefined,'auto',SEAL,'0g-compute','dynamic-image'),/cannot read GET \/config/);
    assert.equal(sealed,false);assert.equal(signed,false);assert.equal(s.posted(),null);
    // Recovery is explicit on the next call, and still resolves the registry.
    assert.equal((await c.getProviderRegistry()).version,0);
  } finally {s.close();}
});

test('concurrent refreshes coalesce only when all discovery constraints agree',async()=>{
  const v2=structuredClone(fixture.snapshot);
  const doc=JSON.parse(v2.document);doc.base_version=1;
  v2.document=JSON.stringify(doc);v2.signature=await operator.signMessage({message:registrySigningMessage(v2.document)});v2.version=2;
  const trust={version:1,digest:fixture.config.provider_registry_digest};
  for (const mode of ['version','digest','same','failure']) {
    let release,entered,reads=0;
    const gate=new Promise(r=>release=r), firstEntered=new Promise(r=>entered=r);
    const srv=createServer(async(req,res)=>{
      const n=++reads;
      if(n===1) {entered();await gate;}
      res.writeHead(mode==='failure'&&n===1?503:200,{'content-type':'application/json'});
      res.end(JSON.stringify(mode==='version'&&n>1?v2:fixture.snapshot));
    });
    await new Promise(r=>srv.listen(0,'127.0.0.1',r));
    try {
      const c=new ProviderRegistryClient(`http://127.0.0.1:${srv.address().port}`);
      const first=c.refresh(trust);const firstResult=first.then(v=>v,e=>e);
      await firstEntered;
      const secondTrust=mode==='version'?{version:2,digest:acceptedRegistryDigest(v2.document,v2.signature)}:
        mode==='digest'?{...trust,digest:'0xwrong'}:mode==='failure'?{...trust,chainId:fixture.chain_id}:trust;
      const second=c.refresh(secondTrust);
      const checked=mode==='digest'?assert.rejects(second,/acceptance digest/):second;
      release();
      const a=await firstResult,b=await checked;
      if(mode==='failure') {assert.match(a.message,/HTTP 503/);assert.equal(b.version,1);}
      else {assert.equal(a.version,1);if(mode!=='digest') assert.equal(b.version,mode==='version'?2:1);}
      assert.equal(reads,mode==='same'?1:2);
    } finally {release();srv.closeAllConnections?.();srv.close();}
  }
});
