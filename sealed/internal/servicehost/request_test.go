package servicehost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const requestFixture = `import os,sys,json,http.server,socket,time
values=json.load(sys.stdin)
print(values,flush=True) # task stdout/stderr must never enter the owner's logs
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_POST(self):
  data=json.loads(self.rfile.read(int(self.headers.get('content-length',0))))
  if data['who']=='crash': os._exit(1)
  time.sleep(data.get('delay',0))
  token=values.get('token','')
  flags={'uid':os.getuid(),'private':token=='runtime-fixture-'+data['who'],
   'header':self.headers.get('X-Seal-Runtime-Input'),
   'fresh':not os.path.exists('/work/witness'),
   'argv':token not in str(sys.argv),
   'proc_private':os.listdir('/proc')==[],
   'env':token not in str(dict(os.environ)),
   'owner_home':os.path.exists('/home/agent'),'sign_socket':os.path.exists('/run/seal-sign.sock'),
   'sealed_state':os.path.exists('/var/lib/sealed'),'secret':os.environ.get('SERVICE_TEST_SECRET')}
  try:
   open('/app/server.py','w');flags['readonly']=False
  except OSError: flags['readonly']=True
  open('/work/witness','w').write(token)
  self.send_response(200);self.end_headers();self.wfile.write(json.dumps(flags).encode())
class Server(http.server.HTTPServer):
 address_family=socket.AF_UNIX
 def server_bind(self): self.socket.bind(self.server_address);self.server_name='task';self.server_port=0
Server(os.environ['MCP_SOCKET'],Handler).serve_forever()
`

func taskManager(t *testing.T, timeout int) *Manager {
	t.Helper()
	root(t)
	if os.Getenv("SEALED_SERVICE_TESTS") != "1" {
		t.Skip("set SEALED_SERVICE_TESTS=1 in a namespace-capable container")
	}
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	man := manifest("task", requestFixture)
	man.RequestTimeoutSeconds = timeout
	if _, err := m.Publish(man); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(man.ID); err != nil {
		t.Fatal(err)
	}
	return m
}

func taskRequest(ctx context.Context, who string, delay float64, version string) *http.Request {
	body, _ := json.Marshal(map[string]any{"who": who, "delay": delay})
	r, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/mcp", bytes.NewReader(body))
	input, _ := json.Marshal(map[string]string{"token": "runtime-fixture-" + who})
	r.Header.Set(RuntimeInputHeader, base64.StdEncoding.EncodeToString(input))
	r.Header.Set(ServiceVersionHeader, version)
	return r
}

func testServiceVersion(m *Manager, id string) string {
	s, _ := m.Match("/api/mcp/" + id)
	return s.Version
}

func TestRequestPrivateInputAndConcurrentIsolation(t *testing.T) {
	m := taskManager(t, 5)
	var wg sync.WaitGroup
	uids := make(chan int, 2)
	for _, who := range []string{"alice", "bob"} {
		wg.Add(1)
		go func(who string) {
			defer wg.Done()
			resp, err := m.HTTPClient("task").Do(taskRequest(context.Background(), who, .4, testServiceVersion(m, "task")))
			if err != nil {
				t.Error(err)
				return
			}
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 {
				t.Errorf("request: %d %s %v", resp.StatusCode, b, err)
				return
			}
			var flags map[string]any
			if err := json.Unmarshal(b, &flags); err != nil {
				t.Error(err)
				return
			}
			for _, k := range []string{"private", "fresh", "argv", "env", "proc_private"} {
				if flags[k] != true {
					t.Errorf("%s failed: %s", k, b)
				}
			}
			if flags["header"] != nil {
				t.Error("runtime header reached HTTP handling")
			}
			uids <- int(flags["uid"].(float64))
		}(who)
	}
	wg.Wait()
	close(uids)
	seen := map[int]bool{}
	for uid := range uids {
		if seen[uid] {
			t.Error("concurrent task UIDs shared")
		}
		seen[uid] = true
	}
	if len(seen) != 2 {
		t.Fatal("did not complete both workers")
	}
	registry, _ := os.ReadFile(filepath.Join(m.base, "registry.json"))
	if strings.Contains(string(registry), "runtime-fixture-") {
		t.Fatal("runtime input persisted")
	}
	logs, _ := m.Logs("task")
	if logs != "" {
		t.Fatal("private task stdout captured")
	}
	dirs, err := os.ReadDir(filepath.Join(m.programs, taskDirName))
	if err != nil || len(dirs) != 0 {
		t.Fatalf("task directories retained: %v %v", dirs, err)
	}
	m.mu.Lock()
	n := len(m.workers)
	m.mu.Unlock()
	if n != 0 {
		t.Fatal("worker identity not released")
	}
	resp, err := m.HTTPClient("task").Do(taskRequest(context.Background(), "again", 0, testServiceVersion(m, "task")))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"fresh": true`) {
		t.Fatalf("reused task state: %s", b)
	}
}

func TestRequestCancellationDeadlineStopAndInputValidation(t *testing.T) {
	m := taskManager(t, 1)
	for _, input := range []string{"invalid", base64.StdEncoding.EncodeToString([]byte(`{"token":1}`)), base64.StdEncoding.EncodeToString([]byte(`null`)), strings.Repeat("A", 24000)} {
		r := taskRequest(context.Background(), "invalid", 0, testServiceVersion(m, "task"))
		r.Header.Set(RuntimeInputHeader, input)
		resp, err := m.HTTPClient("task").Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal("accepted invalid runtime input")
		}
	}
	for _, mode := range []string{"cancel", "deadline", "stop"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				resp, err := m.HTTPClient("task").Do(taskRequest(ctx, mode, 30, testServiceVersion(m, "task")))
				if resp != nil {
					resp.Body.Close()
				}
				done <- err
			}()
			deadline := time.Now().Add(3 * time.Second)
			for {
				m.mu.Lock()
				n := len(m.workers)
				m.mu.Unlock()
				if n > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("worker not admitted")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if mode == "cancel" {
				cancel()
			}
			if mode == "stop" {
				if _, err := m.Stop("task"); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("unfinished task succeeded")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("worker not terminated")
			}
			m.mu.Lock()
			n := len(m.workers)
			m.mu.Unlock()
			if n != 0 {
				t.Fatal("worker leaked")
			}
		})
	}
}

func TestFailedWorkerDoesNotBecomeSharedProcess(t *testing.T) {
	m := taskManager(t, 5)
	resp, err := m.HTTPClient("task").Do(taskRequest(context.Background(), "crash", 0, testServiceVersion(m, "task")))
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("crashed worker returned a successful exchange")
	}
	m.mu.Lock()
	n := len(m.workers)
	m.mu.Unlock()
	if n != 0 {
		t.Fatal("crashed worker retained its identity")
	}
	// The endpoint stays enabled; the next call gets a fresh working directory.
	resp, err = m.HTTPClient("task").Do(taskRequest(context.Background(), "after-crash", 0, testServiceVersion(m, "task")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !strings.Contains(string(b), `"fresh": true`) {
		t.Fatalf("request after crash: %s %v", b, err)
	}
}

func TestRequestLimitsAndStatelessProtocol(t *testing.T) {
	for _, timeout := range []int{-1, 3601} {
		man := manifest("bad", "x")
		man.RequestTimeoutSeconds = timeout
		if _, err := man.normalize(); err == nil {
			t.Fatal("accepted invalid request timeout")
		}
	}
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Publish(manifest("task", "x")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start("task"); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequest(method, "http://localhost/mcp", nil)
		resp, err := m.HTTPClient("task").Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
			t.Fatal("accepted a stateful protocol operation")
		}
	}
	req := taskRequest(context.Background(), "no", 0, testServiceVersion(m, "task"))
	req.Header.Set("Mcp-Session-Id", "previous-session")
	resp, err := m.HTTPClient("task").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("accepted session resumption")
	}
}

func TestWorkerCleanupDoesNotDeleteServiceNamedTasks(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Publish(manifest("tasks", "source-survives-reboot"))
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	reopened, err := newTestManager(m.base, "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b, err := os.ReadFile(filepath.Join(reopened.programs, "tasks", "versions", s.Version, "server.py"))
	if err != nil || string(b) != "source-survives-reboot" {
		t.Fatalf("published source removed during worker cleanup: %q %v", b, err)
	}
}
