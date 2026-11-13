package servicehost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const executionFixture = `import sys,os,json,struct,time,socket,resource
data=sys.stdin.buffer.read()
assert data[:8]==b'SEALRUN1'
private_len,public_len=struct.unpack('>II',data[8:16])
assert len(data)==16+private_len+public_len
runtime=json.loads(data[16:16+private_len])
args=json.loads(data[16+private_len:])
if args.get('fail'): sys.exit(7)
time.sleep(args.get('delay',0))
flags={'uid':os.getuid(),'authorized':bool(runtime.get('token')),
 'label':args.get('label'),'fresh':not os.path.exists('/work/witness'),
 'owner_home':os.path.exists('/home/agent'),'sealed_state':os.path.exists('/var/lib/sealed'),
 'argv_private':runtime.get('token','!') not in str(sys.argv),
 'proc_private':os.listdir('/proc')==[],
 'root_readonly':bool(os.statvfs('/').f_flag & os.ST_RDONLY),
 'tmp_bounded':os.statvfs('/tmp').f_blocks*os.statvfs('/tmp').f_frsize==67108864,
 'work_bounded':os.statvfs('/work').f_blocks*os.statvfs('/work').f_frsize==67108864,
 'core_disabled':resource.getrlimit(resource.RLIMIT_CORE)==(0,0),
 'env_private':runtime.get('token','!') not in str(dict(os.environ))}
try:
 open('/app/worker.py','w');flags['readonly']=False
except OSError: flags['readonly']=True
flags['host_loopback']=False
if args.get('host_addr'):
 host,port=args['host_addr'].rsplit(':',1)
 try:
  conn=socket.create_connection((host,int(port)),timeout=.2);conn.close();flags['host_loopback']=True
 except OSError: pass
open('/work/witness','w').write('temporary')
print(json.dumps(flags),flush=True)
if args.get('output'): sys.stdout.write('x'*args['output'])
`

func executionTestKey(n int) string {
	return fmt.Sprintf("%013d-%032x", time.Now().UnixMilli(), n)
}

func executionManager(t *testing.T) *Manager {
	t.Helper()
	root(t)
	if os.Getenv("SEALED_SERVICE_TESTS") != "1" {
		t.Skip("set SEALED_SERVICE_TESTS=1 in a namespace-capable Linux container")
	}
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	for _, id := range []string{"first", "second"} {
		man := manifest(id, requestFixture)
		man.Worker = &Program{Command: "python3", Args: []string{"/app/worker.py"}}
		man.Files = append(man.Files, File{Path: "worker.py", Data: base64.StdEncoding.EncodeToString([]byte(executionFixture))})
		man.RequestTimeoutSeconds = 5
		if _, err := m.Publish(man); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Start(id); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestDetachedExecutionDeduplicationIsolationAndTransientInput(t *testing.T) {
	m := executionManager(t)
	key := executionTestKey(1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	input := []byte(fmt.Sprintf(`{"delay":0.2,"label":"public-execution-fixture","host_addr":%q}`, listener.Addr().String()))
	private := []byte(`{"token":"private-execution-fixture"}`)
	var wg sync.WaitGroup
	handles := make(chan string, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := m.SpawnExecution("first", key, input, private)
			if err != nil {
				t.Error(err)
				return
			}
			handles <- s.Handle
		}()
	}
	wg.Wait()
	close(handles)
	handle := ""
	for h := range handles {
		if handle != "" && h != handle {
			t.Fatal("concurrent retry started a different execution")
		}
		handle = h
	}
	if handle == "" {
		t.Fatal("execution not started")
	}
	// Dropping a waiter is equivalent to losing a query connection. It must
	// not cancel the detached process owned by the manager.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.WaitExecution(ctx, "first", handle); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	if _, _, err := m.Execution("second", handle, 0); !errors.Is(err, ErrExecutionNotFound) {
		t.Fatal("another service read this execution")
	}
	if err := m.TerminateExecution("second", handle); !errors.Is(err, ErrExecutionNotFound) {
		t.Fatal("another service terminated this execution")
	}
	if _, err := m.SpawnExecution("first", key, []byte(`{"label":"changed"}`), private); !errors.Is(err, ErrExecutionConflict) {
		t.Fatal("a retry changed the bound input")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := m.WaitExecution(ctx, "first", handle)
	if err != nil || s.State != "exited" || s.ExitCode == nil || *s.ExitCode != 0 {
		t.Fatalf("execution: %+v %v", s, err)
	}
	_, output, err := m.Execution("first", handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	var flags map[string]any
	if err := json.Unmarshal(output, &flags); err != nil {
		t.Fatalf("worker output: %q %v", output, err)
	}
	for _, k := range []string{"authorized", "fresh", "argv_private", "env_private", "proc_private", "root_readonly", "tmp_bounded", "work_bounded", "core_disabled", "readonly"} {
		if flags[k] != true {
			t.Fatalf("missing isolation %s: %s", k, output)
		}
	}
	if flags["host_loopback"] != false || flags["owner_home"] != false || flags["sealed_state"] != false || flags["label"] != "public-execution-fixture" {
		t.Fatalf("unexpected environment: %s", output)
	}
	if _, err := os.Stat(filepath.Join(m.programs, "first", "work")); !os.IsNotExist(err) {
		t.Fatal("execution created durable work")
	}
	dirs, err := os.ReadDir(filepath.Join(m.programs, taskDirName))
	if err != nil || len(dirs) != 0 {
		t.Fatalf("execution namespace not collected: %v %v", dirs, err)
	}
	record, err := os.ReadFile(filepath.Join(m.base, "executions", handle+".json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{[]byte("private-execution-fixture"), []byte("public-execution-fixture"), output} {
		if bytes.Contains(record, value) {
			t.Fatal("input or output persisted in process metadata")
		}
	}
	if err := m.ReleaseExecution("first", handle); err != nil {
		t.Fatal(err)
	}
	s, output, err = m.Execution("first", handle, 0)
	if err != nil || len(output) != 0 || s.OutputAvailable {
		t.Fatalf("output acknowledgement: %+v %q %v", s, output, err)
	}
	retry, err := m.SpawnExecution("first", key, input, private)
	if err != nil || retry.Handle != handle || retry.State != "exited" {
		t.Fatal("acknowledgement allowed re-execution")
	}
}

func TestExecutionTerminationFailureAndOutputLimits(t *testing.T) {
	m := executionManager(t)
	for n, tc := range []struct{ input, want string }{
		{`{"delay":30}`, "cancelled"},
		{`{"fail":true}`, "failed"},
		{fmt.Sprintf(`{"output":%d}`, MaxExecutionOutput+1), "failed"},
	} {
		s, err := m.SpawnExecution("first", executionTestKey(n+10), []byte(tc.input), nil)
		if err != nil {
			t.Fatal(err)
		}
		if tc.want == "cancelled" {
			if err := m.TerminateExecution("first", s.Handle); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		final, err := m.WaitExecution(ctx, "first", s.Handle)
		cancel()
		if err != nil || final.State != tc.want {
			t.Fatalf("%s: %+v %v", tc.input, final, err)
		}
	}
	key := fmt.Sprintf("%013d-%s", time.Now().Add(-11*time.Minute).UnixMilli(), strings.Repeat("a", 32))
	if _, err := m.SpawnExecution("first", key, []byte(`{}`), nil); err == nil {
		t.Fatal("old deduplication key could start a new process")
	}
}

func TestRuntimeInputHandoffIsConsumedAtomically(t *testing.T) {
	m := executionManager(t)
	handle, cleanup, err := m.handoff("first", []byte(`{"token":"private-handoff-fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	const attempts = 8
	var wg sync.WaitGroup
	results := make(chan ExecutionStatus, attempts)
	// Queue contenders behind the manager mutex before the first reservation.
	// This exposes a consume-after-unlock gap without relying on worker output.
	m.mu.Lock()
	for i := range attempts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, err := m.spawnWithHandoff("first", executionTestKey(100+i), []byte(`{"delay":0.1}`), handle)
			if err == nil {
				results <- status
			}
		}(i)
	}
	time.Sleep(20 * time.Millisecond)
	m.mu.Unlock()
	wg.Wait()
	close(results)
	var winner ExecutionStatus
	count := 0
	for status := range results {
		winner = status
		count++
	}
	if count != 1 {
		t.Fatalf("one-use private input launched %d executions", count)
	}
	// A lost spawn acknowledgement can still be retried after consumption.
	retry, err := m.spawnWithHandoff("first", winner.Key, []byte(`{"delay":0.1}`), handle)
	if err != nil || retry.Handle != winner.Handle {
		t.Fatalf("same-key retry lost execution: %+v %v", retry, err)
	}
	// A duplicate execution must not consume an unrelated fresh handoff.
	fresh, discard, err := m.handoff("first", []byte(`{"token":"fresh-handoff-fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer discard()
	if _, err := m.spawnWithHandoff("first", winner.Key, []byte(`{"delay":0.1}`), fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := m.spawnWithHandoff("first", executionTestKey(200), []byte(`{}`), fresh); err != nil {
		t.Fatalf("deduplication consumed unused private input: %v", err)
	}
}
