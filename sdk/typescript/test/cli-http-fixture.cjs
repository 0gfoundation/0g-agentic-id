// Full CLI backend fixture. Only HTTP/JSON-RPC is simulated; CLI code is unmodified.
const http = require('node:http');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {encodeAbiParameters, toFunctionSelector} = require('viem');
const {privateKeyToAccount} = require('viem/accounts');
const key = '0x' + '11'.repeat(32);
const owner = privateKeyToAccount(key).address;
const seal = '0x' + '42'.repeat(32);
const agent = '0x' + 'ab'.repeat(20);
const output = process.env.AGENTDNA_CLI_E2E_DIR;
if (!output) throw Error("AGENTDNA_CLI_E2E_DIR is required");
let oldRuntime = false;
let deploymentPhase = 'running';
let deploymentDelay = 0;
let fileDelay = 0;
let base;
const calls = [];
const responses = new Map();
const steers = new Map();
const sessions = new Map([['owner-chat',{id:'owner-chat',title:'owner chat',kind:'owner',state:'idle',created_at:Date.now()/1000,updated_at:Date.now()/1000}]]);
const files = new Map();
let replaceOnAck;
let sessionNumber = 0;
const oldJob = {id:'job-oldest-000001',type:'command',status:'completed',actor:'agent',initiator:'owner',label:'old fixture command',started_at:1,ended_at:2,output_text:'QA_OLDER_THAN_200_OK'};
const recent = Array.from({length:200},(_,i) => ({...oldJob,id:`job-recent-${String(i).padStart(6,'0')}`,output_text:`QA_RECENT_${i}`}));
const abi = new Map([
 ['tokenURI(uint256)', ['string', () => `${base}/card.json`]],
 ['getSealId(uint256)', ['bytes32', () => seal]],
 ['getAgentIdBySealId(bytes32)', ['uint256', () => 42n]],
 ['ownerOf(uint256)', ['address', () => owner]],
 ['getAgentSeal(uint256)', ['address', () => agent]],
].map(([signature,spec]) => [toFunctionSelector(signature),spec]));
const rpc = body => {
  const {id,method,params} = body;
  let result = '0x' + '0'.repeat(64);
  if(method==='eth_chainId') result='0x7a69';
  else if(method==='eth_getBalance') result='0xde0b6b3a7640000';
  else if(method==='eth_blockNumber') result='0x1000';
  else if(method==='eth_call') {
    const spec = abi.get((params[0].data ?? '').slice(0,10));
    if(spec) result=encodeAbiParameters([{type:spec[0]}],[spec[1]()]);
    else return {jsonrpc:'2.0',id,error:{code:3,message:'execution reverted'}};
  }
  return {jsonrpc:'2.0',id,result};
};
const routeKinds = ['chat','responses','activities','inbox','events','files','schedules','sessions','steer'];
const server = http.createServer(async(req,res) => {
  const chunks=[]; for await(const c of req) chunks.push(c);
  let body;try{body=JSON.parse(Buffer.concat(chunks).toString())}catch{}
  const u=new URL(req.url,base);
  const call={at:Date.now(),method:req.method,path:req.url};
  if(req.method==='POST' && !u.pathname.startsWith('/_seal/auth')) call.body=body;
  calls.push(call);
  fs.appendFileSync(path.join(output,'http-fixture-requests.jsonl'),JSON.stringify(call)+'\n');
  const json=(value,status=200)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(value));};
  if(u.pathname==='/fixture-mode'){
    if('old' in (body||{})) oldRuntime=body.old===true;
    if(body?.phase) deploymentPhase=body.phase;
    if('deploymentDelay' in (body||{})) deploymentDelay=Number(body.deploymentDelay)||0;
    if('fileDelay' in (body||{})) fileDelay=Number(body.fileDelay)||0;
    if(body?.clearFiles) { files.clear(); replaceOnAck=undefined; }
    if(body?.file) files.set(body.file.name,Buffer.from(body.file.text));
    if(body?.replaceOnAck) replaceOnAck=body.replaceOnAck;
    return json({oldRuntime,deploymentDelay});
  }
  if(u.pathname==='/fixture-calls')return json(calls);
  if(u.pathname==='/rpc')return json(Array.isArray(body)?body.map(rpc):rpc(body));
  if(u.pathname==='/config')return json({chain_id:31337,chain_rpc:`${base}/rpc`,agentic_id_addr:'0x00000000000000000000000000000000000000A9',frameworks:[{name:'openclaw'},{name:'hermes'},{name:'prime-agent'},{name:'0g-harness'}]});
  const row={seal_id:seal,agent_id:'0x2a',agent_seal_addr:agent,phase:deploymentPhase,framework:'0g-harness',owner,url:base,agent_card:{name:'QA fixture',url:base+'/hello'},created_at:'2026-11-20T00:00:00Z'};
  if(u.pathname==='/deployments'){if(deploymentDelay)await new Promise(r=>setTimeout(r,deploymentDelay));return json([row]);}
  if(u.pathname.startsWith('/deployment/'))return json(row);
  if(u.pathname==='/card.json')return json({url:base});
  if(u.pathname==='/hello')return json({agent,owner,public_url:base,message:'QA fixture',services:[],routes:routeKinds.filter(k=>!(oldRuntime&&k==='sessions')).map(kind=>({prefix:kind==='chat'?'/v1/':`/v1/${kind}`,kind,auth:'bearer',signed:false}))});
  if(u.pathname==='/_seal/auth')return json({token:'qa-fixture-token'});
  if(u.pathname==='/_seal/claim')return json({ok:true});
  if(u.pathname==='/v1/harness')return json({name:'0g-harness',version:oldRuntime?'0.1.0':'0.2.0',features:{sessions:!oldRuntime,files:true,downloads:true,steer:true}});
  if(u.pathname==='/v1/sessions'){
    if(req.method==='POST'){
      const id='sess-matrix-'+String(++sessionNumber).padStart(6,'0');
      const session={id,title:body?.title||'new session',kind:'session',state:'idle',created_at:Date.now()/1000,updated_at:Date.now()/1000,...(body?.fork?{forked_from:body.fork}:{})};
      sessions.set(id,session);return json(session,201);
    }
    return json({data:[...sessions.values()]});
  }
  if(u.pathname.startsWith('/v1/sessions/')){
    const parts=u.pathname.split('/');const session=sessions.get(parts[3]);
    if(!session)return json({error:'no such session'},404);
    if(parts[4]==='cancel')return json({cancelled:null,session:session.id});
    return json(session);
  }
  if(u.pathname==='/v1/files'){
    if(fileDelay)await new Promise(r=>setTimeout(r,fileDelay));
    return json({data:[...files].map(([name,content])=>({name,bytes:content.length,mtime:'2026-11-20T00:00:00Z'}))});
  }
  const ack=/^\/v1\/files\/outbox\/([^/]+)\/ack$/.exec(u.pathname);
  if(ack && req.method==='POST' && !oldRuntime){
    const name=decodeURIComponent(ack[1]);
    if(replaceOnAck?.name===name){files.set(name,Buffer.from(replaceOnAck.text));replaceOnAck=undefined;}
    if(!files.has(name))return json({error:{code:'file_missing'}},404);
    const digest=createHash('sha256').update(files.get(name)).digest('hex');
    if(req.headers['if-match']!=='"'+digest+'"') return json({error:{code:'file_changed'}},412);
    files.delete(name);res.writeHead(204);return res.end();
  }
  if(/^\/v1\/files\/(?:outbox|inbox)\/[^/]+$/.test(u.pathname)){
    const name=decodeURIComponent(u.pathname.split('/').pop());
    if(!files.has(name))return json({error:'no file '+name},404);
    if(req.method==='DELETE'){files.delete(name);return json({ok:true});}
    if(req.method!=='GET')return json({error:'method not allowed'},405);
    res.writeHead(200,{'content-type':'application/octet-stream'});return res.end(files.get(name));
  }
  if(u.pathname==='/v1/inbox')return json({data:[],last_id:0});
  if(u.pathname==='/v1/schedules')return json({enabled:true,data:[{
    id:'sched-repeat',kind:'rrule',status:'active',prompt:'recurring fixture',
    rrule:'DTSTART:20300101T010000Z\nRRULE:FREQ=MINUTELY;INTERVAL=5;COUNT=2',scheduledAt:'2030-01-01T01:00:00Z',
  }]});
  if(u.pathname==='/v1/activities')return json({data:[...recent,oldJob].slice(0,Math.min(500,Number(u.searchParams.get('limit')||50)))});
  if(u.pathname.startsWith('/v1/activities/')) {
    const id=decodeURIComponent(u.pathname.split('/')[3]);
    if(u.pathname.endsWith('/cancel')) {
      if(id==='all')return json({data:[]});
      const v=[oldJob,...recent].find(x=>x.id===id);
      return v?json({id,outcome:'already_done'}):json({error:'no such activity'},404);
    }
    const v=[oldJob,...recent].find(x=>x.id===id);
    return json(v??{error:{message:'no such activity'}},v?200:404);
  }
  if(req.method==='POST' && u.pathname==='/v1/responses') {
    const prompt=JSON.stringify(body);
    const last=(body?.input||[]).filter(m=>m.role==='user').at(-1)?.content;
    if(!String(last).startsWith('QA_'))return json({error:{message:'QA_CHAT_RECEIVED: command reached chat backend'}},400);
    const id='resp_fixture_'+Date.now();responses.set(id,{prompt:String(last),status:'queued'});
    return json({id,object:'response',status:'queued',output_text:''});
  }
  if(req.method==='POST' && /^\/v1\/responses\/[^/]+\/cancel$/.test(u.pathname)){
    const id=u.pathname.split('/')[3];const response=responses.get(id);
    if(!response)return json({error:'not found'},404);
    response.status='cancelled';
    for(const s of steers.values())if(s.turn===id&&s.state==='pending')s.state='dropped';
    return json({id,object:'response',status:'cancelled',output_text:response.text||''});
  }
  if(u.pathname==='/v1/steer' && req.method==='POST'){
    const entry=[...responses].reverse().find(([,r])=>r.status==='in_progress');
    if(!entry)return json({error:'no active fixture turn'},409);
    const id='m-'+Date.now();steers.set(id,{id,state:'pending',turn:entry[0],text:body.text});
    return json({merged:true,id,turn:entry[0]});
  }
  if(u.pathname.startsWith('/v1/steer/'))return json(steers.get(u.pathname.split('/').pop())||{error:'not found'});
  if(req.method==='GET' && u.pathname.startsWith('/v1/responses/')) {
    const id=u.pathname.split('/').pop();const response=responses.get(id);
    if(!response)return json({error:'not found'},404);
    if(u.searchParams.get('stream')!=='true')return json({id,object:'response',status:response.status,output_text:response.text||''});
    const prompt=response.prompt;
    res.writeHead(200,{'content-type':'text/event-stream','cache-control':'no-cache'});
    let seq=0;
    const frame=(type,extra)=>res.write(`id: ${++seq}\nevent: ${type}\ndata: ${JSON.stringify({type,sequence_number:seq,...extra})}\n\n`);
    response.status='in_progress';
    frame('response.created',{response:{id,object:'response',status:'in_progress'}});
    let text='';
    if(prompt.startsWith('QA_SLOW')){
      for(let i=0;i<80 && response.status!=='cancelled';i++){
        res.write(': keepalive\n\n');await new Promise(r=>setTimeout(r,100));
      }
      if(response.status==='cancelled'){
        frame('response.completed',{response:{id,object:'response',status:'cancelled',output_text:''}});return res.end();
      }
    }
    for(let i=1;i<=6;i++) {
      if(prompt.includes('QA_INTERLEAVED')) {const delta=`QA_COMMENT_${i}\n`;text+=delta;frame('response.output_text.delta',{delta});}
      frame('response.activity',{label:'tool/call bash'});
      await new Promise(r=>setTimeout(r,90));
      frame('response.activity',{label:'tool/result bash'});
    }
    text+='QA_STREAM_DONE';frame('response.output_text.delta',{delta:'QA_STREAM_DONE'});
    response.status='completed';response.text=text;
    frame('response.completed',{response:{id,object:'response',status:'completed',output_text:text}});
    return res.end();
  }
  return json({error:{message:'fixture: no such route'}},404);
});
server.listen(0,'127.0.0.1',()=>{
  base=`http://127.0.0.1:${server.address().port}`;
  const configRoot=path.join(output,'fixture-config');
  const dir=path.join(configRoot,'0g-agentdna');fs.mkdirSync(dir,{recursive:true});
  fs.writeFileSync(path.join(dir,'config.json'),JSON.stringify({attestorUrl:base,filesAuto:'off'}));
  fs.writeFileSync(path.join(dir,'credentials'),JSON.stringify({privateKey:key}),{mode:0o600});
  fs.writeFileSync(path.join(output,'http-fixture.json'),JSON.stringify({base,configRoot,oldId:oldJob.id,pid:process.pid}));
  fs.appendFileSync(path.join(output,'http-fixture-lifecycle.jsonl'),JSON.stringify({base,pid:process.pid})+'\n');
  console.log(JSON.stringify({ready:true,base,configRoot,pid:process.pid}));
});
