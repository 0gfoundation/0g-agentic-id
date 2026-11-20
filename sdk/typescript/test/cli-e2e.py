"""CLI black-box matrix: real PTY + unmodified CLI + HTTP/RPC/SSE fixture."""
import errno, fcntl, json, os, pty, re, select, signal, struct, sys, termios, time
import urllib.request
import argparse, shutil, subprocess, tempfile
from pathlib import Path

ARGS=argparse.ArgumentParser(description=__doc__)
ARGS.add_argument('--output-dir', type=Path)
OPTIONS=ARGS.parse_args()
SOURCE=Path(__file__).resolve().parent
TEMP=None if OPTIONS.output_dir else tempfile.TemporaryDirectory(prefix='agentdna-cli-e2e-')
ROOT=(OPTIONS.output_dir or Path(TEMP.name)).resolve()
ROOT.mkdir(parents=True,exist_ok=True)
NODE=os.environ.get('NODE_BINARY') or shutil.which('node')
if not NODE:raise RuntimeError('node is required')
MAIN=str(SOURCE.parent/'dist'/'cli'/'main.js')
fixture_env={k:v for k,v in os.environ.items() if not k.startswith('AGENTIC_') and k!='NODE_OPTIONS'}
fixture_env['AGENTDNA_CLI_E2E_DIR']=str(ROOT)
FIXTURE=subprocess.Popen([NODE,str(SOURCE/'cli-http-fixture.cjs')],env=fixture_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
ready=FIXTURE.stdout.readline()
if not ready:raise RuntimeError(FIXTURE.stderr.read())
FIX=json.loads((ROOT/'http-fixture.json').read_text())
BASE=FIX['base']
# Isolate generated downloads as well as config without touching the real home.
PRELOAD=ROOT/'local-home.cjs'
PRELOAD.write_text("require('node:os').homedir = () => "+json.dumps(str(ROOT/'home'))+";\n")
ANSI=re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[=>]')
results=[]
ONLY=set(filter(None,os.environ.get('CLI_MATRIX_CASES','').split('|')))
PREFIX='cli-matrix-targeted' if ONLY else 'cli-matrix'

def api(route,body=None):
    data=None if body is None else json.dumps(body).encode()
    req=urllib.request.Request(BASE+route,data=data,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=10) as r:return json.load(r)

def calls():return api('/fixture-calls')
def chats(rows):return [x for x in rows if x['method']=='POST' and x['path']=='/v1/responses']
def last_text(rows):
    c=chats(rows)
    if not c:return None
    user=[m for m in c[-1].get('body',{}).get('input',[]) if m.get('role')=='user']
    return user[-1].get('content') if user else None

class Terminal:
    def __init__(self,mode,capture=None):
        self.mode=mode; self.capture=capture or mode; self.raw=bytearray();self.inputs=[]
        config=ROOT/('matrix-config-'+mode)/'0g-agentdna';config.mkdir(parents=True,exist_ok=True)
        for name in ['config.json','credentials']:(config/name).write_bytes((Path(FIX['configRoot'])/'0g-agentdna'/name).read_bytes())
        (config/'credentials').chmod(0o600)
        self.pid,self.fd=pty.fork()
        if self.pid==0:
            # The fixture wallet and URLs must win over a developer's real
            # account/environment, even when this suite is launched there.
            for k in list(os.environ):
                if k.startswith('AGENTIC_') or k=='NODE_OPTIONS':del os.environ[k]
            os.environ['XDG_CONFIG_HOME']=str(config.parent)
            os.environ['TERM']='xterm-256color';os.environ['NO_COLOR']='1';os.environ['AGENTDNA_INK']='on' if mode=='ink' else 'off'
            for k in list(os.environ):
                if k=='CI' or k=='CONTINUOUS_INTEGRATION' or k.startswith('CI_'):del os.environ[k]
            fcntl.ioctl(0,termios.TIOCSWINSZ,struct.pack('HHHH',24,80,0,0))
            os.execv(NODE,[NODE,'--require',str(PRELOAD),MAIN,'42'])
        self.read(2)
    def read(self,seconds=.35):
        buf=bytearray();end=time.monotonic()+seconds
        while time.monotonic()<end:
            if not select.select([self.fd],[],[],min(.05,max(.001,end-time.monotonic())))[0]:continue
            try:b=os.read(self.fd,65536)
            except OSError as e:
                if e.errno==errno.EIO:break
                raise
            if not b:break
            buf.extend(b)
        self.raw.extend(buf)
        return ANSI.sub('',buf.decode('utf-8','replace')).replace('\r','')
    def send(self,text,wait=.35):
        self.inputs.append({'at':time.time(),'text':text,'raw_offset':len(self.raw)})
        os.write(self.fd,text.encode());return self.read(wait)
    def clear(self):return self.send('\x15',.15)
    def close(self):
        try:self.send('\x15/quit\r',.3)
        except OSError:pass
        try:os.kill(self.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        os.waitpid(self.pid,0);os.close(self.fd)
        (ROOT/('cli-matrix-'+self.capture+'.ansi')).write_bytes(self.raw)
        (ROOT/('cli-matrix-'+self.capture+'.txt')).write_text(ANSI.sub('',self.raw.decode('utf-8','replace')).replace('\r',''))
        (ROOT/('cli-matrix-'+self.capture+'-inputs.json')).write_text(json.dumps(self.inputs,ensure_ascii=False,indent=2))

def require(value,message):
    if not value:raise AssertionError(message)

def run_case(t,name,fn):
    if ONLY and name not in ONLY:return
    before=len(calls());start=len(t.raw);input_start=len(t.inputs)
    try:
        detail=fn(before) or {};result={'mode':t.mode,'case':name,'status':'pass','detail':detail}
    except Exception as e:result={'mode':t.mode,'case':name,'status':'fail','error':str(e)}
    result['inputs']=t.inputs[input_start:];result['terminal_excerpt']=ANSI.sub('',bytes(t.raw[start:]).decode('utf-8','replace')).replace('\r','')[-5000:]
    results.append(result)
    (ROOT/(PREFIX+'-results.json')).write_text(json.dumps(results,ensure_ascii=False,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k not in ['inputs','terminal_excerpt']},ensure_ascii=False),flush=True)

def test_command(t,command,want,typed_pieces=None):
    before=len(calls())
    if typed_pieces:
        out=''
        for part in typed_pieces:out+=t.send(part,.2)
        out+=t.send('\r',.7)
    else:out=t.send(command+'\r',.7)
    seen=calls()[before:]
    require(not chats(seen),'command was submitted to chat: '+repr(last_text(seen)))
    require(want in out,'expected terminal text missing: '+want)

def test_message(t,pieces,expected):
    before=len(calls())
    for part in pieces:t.send(part,.2)
    t.send('\r',.7)
    text=last_text(calls()[before:]);require(text==expected,'backend received '+repr(text)+' instead of '+repr(expected))

def main():
    for mode in ['ink','plain']:
        api('/fixture-mode',{'old':False,'deploymentDelay':0,'clearFiles':True})
        t=Terminal(mode)
        try:
            run_case(t,'typed /help stays a command',lambda _:test_command(t,'/help','session commands'))
            run_case(t,'pasted /help stays a command',lambda _:test_command(t,'','session commands',['\x1b[200~/help\x1b[201~']))
            run_case(t,'typed slash with pasted argument stays a command',lambda _:test_command(t,'','QA_RECENT_1',['/result ','\x1b[200~job-recent-000001\x1b[201~']))
            run_case(t,'pasted command plus trailing newline stays a command',lambda _:test_command(t,'','session commands',['\x1b[200~/help\n\x1b[201~']))
            run_case(t,'paste end and Enter in the same read submits the command',lambda _:test_command(t,'\x1b[200~/help\x1b[201~','session commands'))
            run_case(t,'pasted argument and Enter in the same read stays a command',lambda _:test_command(t,'/result \x1b[200~job-recent-000001\x1b[201~','QA_RECENT_1'))
            run_case(t,'paste trailing newline and Enter in the same read submits',lambda _:test_command(t,'\x1b[200~/help\n\x1b[201~','session commands'))
            run_case(t,'multiline pasted document stays one chat message',lambda _:test_message(t,['\x1b[200~/help\nthis is quoted document text\x1b[201~',''],'/help\nthis is quoted document text'))
            for quote,label in [('"','double'),("'",'single'),('`','backtick')]:
                run_case(t,label+'-quoted activity ID',lambda _,q=quote:test_command(t,'/result '+q+'job-recent-000001'+q,'QA_RECENT_1'))
            run_case(t,'bare activity ID',lambda _:test_command(t,'/result job-recent-000001','QA_RECENT_1'))
            run_case(t,'full old activity ID',lambda _:test_command(t,'/result job-oldest-000001','QA_OLDER_THAN_200_OK'))
            run_case(t,'short old activity ID',lambda _:test_command(t,'/result job-oldest','QA_OLDER_THAN_200_OK'))
            def cancel_quoted(before):
                out=t.send('/cancel "job-recent-000001"\r',.7)
                seen=calls()[before:]
                require(any(x['path']=='/v1/activities/job-recent-000001/cancel' for x in seen),'quoted ID not decoded before cancel request')
            run_case(t,'quoted cancel activity ID',cancel_quoted)
            run_case(t,'Alt+Enter preserves a single multiline message',lambda _:test_message(t,['alpha','\x1b\r','beta'],'alpha\nbeta'))
            run_case(t,'Ctrl+U clears every draft line',lambda _:test_message(t,['first','\x1b\r','second','\x15','after clear'],'after clear'))
            run_case(t,'typing 200ms after Esc clears draft without sending it',lambda _:test_message(t,['discard me','\x1b','kept text'],'kept text'))
            def slow_escape(before):
                t.send('discard me',.2);t.send('\x1b',.8);t.send('kept text',.2);t.send('\r',.7)
                require(last_text(calls()[before:])=='kept text','Esc still failed after waiting 800ms')
            run_case(t,'typing 800ms after Esc clears draft',slow_escape)
            run_case(t,'Unicode cursor editing keeps intended text',lambda _:test_message(t,['中文abcdef','\x1b[D\x1b[D\x1b[D','XYZ'],'中文abcXYZdef'))
            run_case(t,'Tab completes /sess to /sessions',lambda _:test_command(t,'','owner-chat',['/sess\t']))
            def unknown(before):
                out=t.send('/qa-command-does-not-exist\r',.7)
                require(not chats(calls()[before:]),'unknown slash command was sent to agent')
                require('unknown' in out.lower() or 'help' in out.lower(),'no command error shown')
            run_case(t,'unknown slash command is rejected locally',unknown)
            title="Matrix "+mode+" team's research "+str(int(time.time()))
            def new_session(before):
                t.send('/sessions new '+title+'\r',.6)
                seen=calls()[before:]
                require(any(x['path']=='/v1/sessions' and x['method']=='POST' and x['body'].get('title')==title for x in seen),'title changed at create')
            run_case(t,'new session title with spaces',new_session)
            def switch_unquoted(before):
                t.send('/sessions default\r',.4)
                test_command(t,'/sessions switch '+title,'→ '+title)
            def switch_quoted(before):
                t.send('/sessions default\r',.4)
                test_command(t,'/sessions switch "'+title+'"','→ '+title)
            run_case(t,'switch session by unquoted title',switch_unquoted)
            run_case(t,'switch session by quoted title',switch_quoted)
            run_case(t,'return to owner-chat',lambda _:test_command(t,'/sessions default','owner-chat'))
            def busy_readonly(before):
                t.send('QA_SLOW_READONLY\r',.5);t.send('/activities\r',.5)
                mid=calls()[before:]
                t.send('\x1b',.9);t.clear()
                require(len(chats(mid))==1,'read-only command created another chat turn')
                require(any(x['path'].startswith('/v1/activities?') for x in mid),'read-only command did not run during turn')
                require(not any(x['path']=='/v1/steer' for x in mid),'read-only command was steered as text')
                require(any(x['path'].endswith('/cancel') and '/v1/responses/' in x['path'] for x in calls()[before:]),'Esc did not cancel on server')
            run_case(t,'read-only command works during a turn; Esc cancels',busy_readonly)
            def steer(before):
                t.send('QA_SLOW_STEER\r',.5);t.send('unread owner message\r',.5)
                mid=calls()[before:];out=t.send('\x1b',1);t.clear()
                require(any(x['path']=='/v1/steer' and x.get('body',{}).get('text')=='unread owner message' for x in mid),'Enter did not use steer endpoint')
                require(len(chats(mid))==1,'steer opened an extra chat submission')
                require('unread owner message' in out,'unread message was not returned after server cancelled it')
            run_case(t,'Enter steers; Esc returns unread message',steer)
            def queued(before):
                t.send('QA_SLOW_QUEUE\r',.5);t.send('queued owner message\t',.4)
                mid=calls()[before:];out=t.send('\x1b',1);t.clear()
                require(len(chats(mid))==1,'Tab submitted next-turn message immediately')
                require(not any(x['path']=='/v1/steer' for x in mid),'Tab message was sent as steer')
                require('queued owner message' in out,'queued message was not returned after Esc')
            run_case(t,'Tab queues; Esc returns queued message',queued)
            run_case(t,'/help still works after interrupted turns',lambda _:test_command(t,'/help','session commands'))
            api('/fixture-mode',{'file':{'name':'qa 中文 #file.txt','text':'QA_MATRIX_FILE_OK'}})
            dest=ROOT/('matrix-download-'+mode+'.txt')
            for suffix in ['', '-1']:
                p=dest if not suffix else dest.with_name(dest.stem+suffix+dest.suffix)
                if p.exists():p.unlink()
            def download(before):
                t.send('/download "qa 中文 #file.txt" "'+str(dest)+'"\r',.7)
                require(dest.exists() and dest.read_text()=='QA_MATRIX_FILE_OK','quoted Unicode filename or destination failed')
            run_case(t,'download quoted Unicode filename',download)
            def no_overwrite(before):
                dest.write_text('LOCAL_ORIGINAL')
                t.send('/download "qa 中文 #file.txt" "'+str(dest)+'"\r',.7)
                require(dest.read_text()=='LOCAL_ORIGINAL','existing file overwritten')
                p=dest.with_name(dest.stem+'-1'+dest.suffix)
                require(p.exists() and p.read_text()=='QA_MATRIX_FILE_OK','collision copy missing')
            run_case(t,'download preserves existing local file',no_overwrite)
            api('/fixture-mode',{'clearFiles':True})
            t.send('/back\r',.6)
            for command in ['deposit -1','deposit abc','withdraw 0']:
                def bad_amount(before,c=command):
                    out=t.send(c+'\r',.6)
                    require('error' in out.lower(),'bad amount accepted')
                    writes=[x for x in calls()[before:] if x['path']=='/rpc' and 'send' in str(x.get('body',''))]
                    require(not writes,'invalid amount submitted transaction')
                run_case(t,'manager rejects '+command,bad_amount)
            def history(before):
                t.send('deploy\r',.5);at_question=t.send('\x1b[A',.25)
                t.send('\x1b',.8);back=t.send('\x1b[A',.3);t.clear()
                require('deploy' not in at_question,'question recalled manager command history')
                require('deploy' in back,'manager history not restored after cancelled question')
            run_case(t,'history is isolated at wizard question and restored',history)
            def wait_keys(before):
                api('/fixture-mode',{'deploymentDelay':1200})
                out=t.send('list\r',.15);out+=t.send('whoami\r',1.8)
                api('/fixture-mode',{'deploymentDelay':0})
                require('not kept' in out,'no note about keys discarded during manager command')
            run_case(t,'manager type-ahead during wait is discarded and explained',wait_keys)
            run_case(t,'manager returns to a working session',lambda _:test_command(t,'use 42','agent 42 session'))
            def older_runtime(before):
                t.send('/back\r',.3);api('/fixture-mode',{'old':True})
                t.send('use 42\r',.7)
                try:test_command(t,'/sessions','this runtime does not expose sessions')
                finally:
                    t.send('/back\r',.3);api('/fixture-mode',{'old':False});t.send('use 42\r',.7)
            run_case(t,'older harness gets a runtime capability message',older_runtime)
            def deploy_default(before):
                t.send('/back\r',.3)
                out=t.send('deploy\r',1)
                try:require(re.search(r'0g-harness\s+\(default\)',out),'harness is not the deployment default')
                finally:t.send('\x03',.5);t.send('use 42\r',.7)
            run_case(t,'deploy defaults to 0g-harness',deploy_default)
        finally:t.close()

    for phase in ['stopped','running']:
        api('/fixture-mode',{'phase':phase,'old':False,'clearFiles':True})
        t=Terminal('ink','lifecycle-'+phase)
        try:
            if phase=='stopped':
                api('/fixture-mode',{'phase':'running'})
                t.read(11)  # the actual session's 10 s phase poll connects
            def automatic_file(before):
                name='qa-lifecycle-'+phase+'.txt'
                api('/fixture-mode',{'fileDelay':250,'file':{'name':name,'text':'QA_LIFECYCLE_OK'}})
                output=t.send('/files auto on\r',2)
                local=ROOT/'home'/'agentdna'/'42'/'outbox'/name
                require(local.exists() and local.read_text()=='QA_LIFECYCLE_OK','automatic download did not save the exact bytes')
                require(any(c['method']=='DELETE' and c['path'].endswith(name) for c in calls()[before:]),'remote file was not deleted')
                require(not api('/v1/files')['data'],'outbox still has the downloaded file')
                require(output.count('saved '+name)==1,'overlapping checks announced the same save more than once')
            run_case(t,'automatic download and cleanup after entering '+phase,automatic_file)
        finally:t.close()

    summary={'total':len(results),'pass':sum(x['status']=='pass' for x in results),'fail':sum(x['status']=='fail' for x in results),'failures':[{'mode':x['mode'],'case':x['case'],'error':x['error']} for x in results if x['status']=='fail']}
    (ROOT/(PREFIX+'-summary.json')).write_text(json.dumps(summary,ensure_ascii=False,indent=2))
    print(json.dumps({'summary':summary},ensure_ascii=False),flush=True)

if __name__=='__main__':
    try:
        main()
        if any(r['status']=='fail' for r in results):sys.exit(1)
    finally:
        FIXTURE.terminate()
        FIXTURE.wait(timeout=10)
        if TEMP:TEMP.cleanup()
