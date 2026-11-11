package servicehost

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func manifest(id, source string) Manifest {
	return Manifest{ID: id, Command: "python3", Args: []string{"/app/server.py"}, Files: []File{{Path: "server.py", Data: base64.StdEncoding.EncodeToString([]byte(source))}}}
}

func root(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("SEALED_SERVICE_TESTS") == "1" {
			t.Fatal("service tests require root")
		}
		t.Skip("requires root")
	}
}

func TestManifestBounds(t *testing.T) {
	for _, p := range []string{"../key", "/root/key", "a/../../key", "a/./key", "a//key", "a\\key", "."} {
		m := manifest("demo", "x")
		m.Files[0].Path = p
		if _, err := m.normalize(); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	m := manifest("demo", "x")
	m.Files = append(m.Files, m.Files[0])
	if _, err := m.normalize(); err == nil {
		t.Fatal("accepted duplicate")
	}
	m = manifest("demo", "x")
	m.Env = map[string]string{"LD_PRELOAD": "/bad"}
	if _, err := m.normalize(); err == nil {
		t.Fatal("accepted reserved env")
	}
}

func TestPublishBindingAndImmutableRelease(t *testing.T) {
	root(t)
	dir := filepath.Join(t.TempDir(), "services")
	m, err := New(dir, "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	man := manifest("demo", "v1")
	s, err := m.Publish(man)
	if err != nil {
		t.Fatal(err)
	}
	man.Files[0].Data = base64.StdEncoding.EncodeToString([]byte("v2"))
	next, err := m.Publish(man)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version == next.Version {
		t.Fatal("version did not change")
	}
	b, err := os.ReadFile(filepath.Join(m.programs, "demo", "versions", s.Version, "server.py"))
	if err != nil || string(b) != "v1" {
		t.Fatalf("old version changed: %s %v", b, err)
	}
	reloaded, err := New(dir, "owner:identity")
	if err != nil || reloaded.List()[0].Version != next.Version {
		t.Fatalf("reload: %v", err)
	}
	if _, err := New(dir, "another-owner:identity"); err == nil {
		t.Fatal("resumed another owner's services")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(dir, "link"), "owner:identity"); err == nil {
		t.Fatal("followed symlink")
	}
}

const fixture = `import os, socket, http.server, json
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def do_GET(self):
  flags={"uid":os.getuid(),"owner_home":os.path.exists("/home/agent"),"sign_socket":os.path.exists("/run/seal-sign.sock"),"sealed_state":os.path.exists("/var/lib/sealed"),"other_work":os.path.exists("/work-other"),"secret":os.environ.get("SERVICE_TEST_SECRET")}
  try:
   open("/app/server.py","w");flags["readonly"]=False
  except OSError: flags["readonly"]=True
  open("/work/witness","w").write("persistent")
  self.send_response(200);self.end_headers();self.wfile.write(json.dumps(flags).encode())
class Server(http.server.HTTPServer):
 address_family=socket.AF_UNIX
 def server_bind(self): self.socket.bind(self.server_address);self.server_name="service";self.server_port=0
Server(os.environ["MCP_SOCKET"],Handler).serve_forever()
`

func running(t *testing.T, m *Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range m.List() {
			if s.ID == id && s.State == "running" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	log, _ := m.Logs(id)
	t.Fatalf("service never ready: %+v\n%s", m.List(), log)
}

func TestSandboxLifecycleAndIsolation(t *testing.T) {
	root(t)
	if os.Getenv("SEALED_SERVICE_TESTS") != "1" {
		t.Skip("set SEALED_SERVICE_TESTS=1 in a namespace-capable container")
	}
	t.Setenv("SERVICE_TEST_SECRET", "not-for-the-child")
	m, err := New(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, id := range []string{"first", "second"} {
		if _, err = m.Publish(manifest(id, fixture)); err != nil {
			t.Fatal(err)
		}
		if _, err = m.Start(id); err != nil {
			t.Fatal(err)
		}
		running(t, m, id)
	}
	if m.List()[0].UID == m.List()[1].UID {
		t.Fatal("shared service identity")
	}
	client := Client(m.socket("first"))
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://localhost/mcp")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{`"uid": 200000`, `"owner_home": false`, `"sign_socket": false`, `"sealed_state": false`, `"secret": null`, `"readonly": true`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("isolation missing %s: %s", want, b)
		}
	}
	if _, err = m.Publish(manifest("first", "changed")); err == nil {
		t.Fatal("updated a running service")
	}
	// Crash the supervisor. The PID namespace removes its descendants; a
	// fresh socket becomes ready and the other service stays running.
	m.mu.Lock()
	pid := m.entries["first"].cmd.Process
	oldgen := m.entries["first"].generation
	m.mu.Unlock()
	_ = pid.Kill()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		gen := m.entries["first"].generation
		m.mu.Unlock()
		if gen > oldgen {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	running(t, m, "first")
	if _, err = m.Stop("first"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2200 * time.Millisecond)
	for _, s := range m.List() {
		if s.ID == "first" && (s.State != "stopped" || s.Desired) {
			t.Fatalf("resurrected: %+v", s)
		}
		if s.ID == "second" && s.State != "running" {
			t.Fatal("stop affected another service")
		}
	}
	// Reboot preserves desired state, not a stale PID/readiness claim.
	m.Close()
	restored, err := New(m.base, "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restored.Resume()
	running(t, restored, "second")
	for _, s := range restored.List() {
		if s.ID == "first" && s.State != "stopped" {
			t.Fatal("reboot restarted a stopped service")
		}
	}
	if _, err = os.Stat(filepath.Join(m.programs, "first", "work", "witness")); err != nil {
		t.Fatal(fmt.Errorf("work did not persist: %w", err))
	}
}
