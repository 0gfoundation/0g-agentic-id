import { test } from 'node:test'
import assert from 'node:assert/strict'
import { makeAgentClient } from '../dist/AgentClient.js'
import { nativeResources } from '../dist/NativeResources.js'
import { nativeCommand, nativeHelp } from '../dist/cli/nativeCommands.js'
const routes = [{ prefix: '/v1/sessions', kind: 'zgh-sessions-v1', auth: 'bearer', signed: false }, { prefix: '/v1/tasks', kind: 'zgh-tasks-v1', auth: 'bearer', signed: false }]
test('native resources are capability gated and do not attach legacy task methods', () => {
 const c=makeAgentClient({base:'http://agent',services:[],routes,token:'owner'})
 assert.ok(c.nativeSessions); assert.ok(c.nativeTasks); assert.equal(c.tasks,undefined);assert.equal(c.taskInfo,undefined)
 for(const old of ['openclaw','hermes','prime-agent']){
  const c=makeAgentClient({base:'http://agent',services:[],routes:[{prefix:'/v1/',kind:'chat',auth:'bearer',signed:false}],token:'owner'})
  assert.equal(c.nativeSessions,undefined,old);assert.equal(c.nativeTasks,undefined,old);assert.equal(nativeHelp(c),undefined)
 }
 assert.equal(makeAgentClient({base:'http://agent',services:[],routes}).nativeTasks,undefined)
})
test('native request payloads and SSE preserve the resource protocol', async () => {
 const seen=[]; const api=nativeResources('/v1/tasks',async(path,init)=>{
  seen.push({path,init})
  if(path.includes('/events'))return new Response('id: 2\nevent: turn/end\ndata: {"seq":2}\n\n',{headers:{'content-type':'text/event-stream'}})
  return Response.json({id:'task-1',state:'needs-input'})
 })
 await api.create({prompt:'work',start:false});await api.input('task-1','more');await api.archive('task-1')
 const events=[];for await(const e of api.events('task-1',{after:1}))events.push(e)
 assert.deepEqual(JSON.parse(seen[0].init.body),{prompt:'work',start:false})
 assert.equal(seen[1].path,'/v1/tasks/task-1/input');assert.deepEqual(JSON.parse(seen[1].init.body),{text:'more'})
 assert.equal(seen[2].path,'/v1/tasks/task-1/archive');assert.deepEqual(events,[{id:'2',event:'turn/end',data:{seq:2}}])
})
test('CLI native commands dispatch by capability and retain multiword input', async()=>{
 const seen=[]; const c={nativeSessions:{create:async body=>{seen.push(body);return{id:'s'}}},nativeTasks:{input:async(id,text)=>{seen.push({id,text});return{ok:true}},get:async id=>({id,state:'done'})}}
 const output=[];const out=s=>output.push(s)
 assert.equal(await nativeCommand(c,'/session fork old',out),true);assert.deepEqual(seen[0],{fork:'old'})
 assert.equal(await nativeCommand(c,'/task input task-1 more than one word',out),true);assert.deepEqual(seen[1],{id:'task-1',text:'more than one word'})
 assert.equal(await nativeCommand(c,'/result task-1',out),true);assert.match(output.at(-1),/done/)
 assert.equal(await nativeCommand({},'/task input task-1 hello',out),false)
 assert.match(nativeHelp(c),/session fork|resume\|fork/);assert.doesNotMatch(nativeHelp(c),/\/inbox/)
})
test('native commands preserve synthesized Responses turn ids', async()=>{
 const c={task:async()=>({id:'resp_1'}),nativeTasks:{get:async()=>{throw new Error('native route must not be used')}}}
 assert.equal(await nativeCommand(c,'/result',()=>{}),false)
 assert.equal(await nativeCommand(c,'/result resp_1',()=>{}),false)
 assert.equal(await nativeCommand(c,'/cancel resp_1',()=>{}),false)
})
