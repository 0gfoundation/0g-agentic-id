package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"seal-verify/internal/privsep"
	"seal-verify/internal/report"
)

func TestValidateStart(t *testing.T) {
	home := privsep.AgentHome()
	ok := []*ServiceStart{nil, {Command: "sh", Args: []string{"server.sh"}}, {Command: "sh", Dir: home}, {Command: "sh", Dir: home + "/site"},
		{Command: home + "/bin/serve"}}
	for _, s := range ok {
		if err := validateStart(s); err != nil {
			t.Errorf("%+v refused: %v", s, err)
		}
	}
	bad := []*ServiceStart{
		{Command: ""},
		{Command: "a\x00b"},
		{Command: strings.Repeat("a", maxStartCommand+1)},
		{Command: "sh", Args: make([]string, maxStartArgs+1)},
		{Command: "sh", Args: []string{"a\x00"}},
		{Command: "sh", Dir: "site"},
		{Command: "sh", Dir: "/etc"},
		{Command: "sh", Dir: home + "/../etc"},
		{Command: "sh", Dir: home + "x"},
		{Command: "bin/serve"},                  // relative: nothing sealed could resolve
		{Command: "./serve"},                    // likewise
		{Command: home + "/bin/../serve"},       // not clean
		{Command: "no-such-command-sealed-xyz"}, // not a system command
	}
	for _, s := range bad {
		if err := validateStart(s); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

func register(t *testing.T, s *Server, entries []ServiceEntry) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"services": entries})
	out := httptest.NewRecorder()
	s.handleServices(out, httptest.NewRequest("POST", "/services", strings.NewReader(string(body))))
	if out.Code != http.StatusOK {
		t.Fatalf("register: %d %s", out.Code, out.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(out.Body.Bytes(), &got)
	return got
}

func TestOneStartCommandPerBackend(t *testing.T) {
	a := &ServiceStart{Command: "sh", Args: []string{"a.sh"}}
	b := &ServiceStart{Command: "sh", Args: []string{"b.sh"}}
	two := []ServiceEntry{
		{Path: "/api/a", Method: "GET", Backend: "http://127.0.0.1:8090", Start: a},
		{Path: "/api/b", Method: "GET", Backend: "http://localhost:8090", Start: b},
	}
	if _, err := validateServices(two, fieldLimits{}); err == nil {
		t.Fatal("two start commands for one backend accepted")
	}
	two[1].Start = a
	if _, err := validateServices(two, fieldLimits{}); err != nil {
		t.Fatalf("one start command named twice refused: %v", err)
	}
	two[1].Start = nil
	if _, err := validateServices(two, fieldLimits{}); err != nil {
		t.Fatalf("an entry without a start command on a started backend refused: %v", err)
	}
}

func TestAgentInterfacesKeptAcrossRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent-services.json")
	rt := AgentServiceRuntime{StateFile: state, Binding: "0xowner:0xseal"}
	first := &Server{}
	first.RestoreAgentServices(rt)
	entries := []ServiceEntry{{Path: "/api/report", Method: "get", Backend: "http://127.0.0.1:8090", Description: "report"}}
	if got := register(t, first, entries); got["warning"] != nil {
		t.Fatalf("not kept: %v", got["warning"])
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("registration not written: %v", err)
	}
	// A restart: a new server under the same owner and seal has it back.
	again := &Server{}
	again.RestoreAgentServices(rt)
	if e, ok := again.matchService("/api/report"); !ok || e.Method != "GET" || e.Backend != "http://127.0.0.1:8090" {
		t.Fatalf("not restored: %+v %v", e, ok)
	}
	// Another owner or agent: dropped, file and all.
	other := &Server{}
	other.RestoreAgentServices(AgentServiceRuntime{StateFile: state, Binding: "0xother:0xseal"})
	if _, ok := other.matchService("/api/report"); ok {
		t.Fatal("restored for another binding")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("file of another binding kept: %v", err)
	}
	// A saved entry that no longer passes registration is dropped on its own.
	bad, _ := json.Marshal(agentServiceFile{V: 1, Binding: rt.Binding, Services: []ServiceEntry{
		{Path: "/api/report", Method: "GET", Backend: "http://127.0.0.1:8090"},
		{Path: "/hello/x", Method: "GET", Backend: "http://127.0.0.1:8091"},
	}})
	if err := os.WriteFile(state, bad, 0600); err != nil {
		t.Fatal(err)
	}
	partly := &Server{}
	partly.RestoreAgentServices(rt)
	if _, ok := partly.matchService("/api/report"); !ok {
		t.Fatal("a valid entry dropped with an invalid one")
	}
	if got := partly.getServices(); len(got) != 1 {
		t.Fatalf("restored %d entries, want 1", len(got))
	}
	if b, _ := os.ReadFile(state); strings.Contains(string(b), "/hello/x") {
		t.Fatal("the dropped entry is still saved")
	}
	// Before RestoreAgentServices a registration is not written anywhere.
	unbound := &Server{}
	register(t, unbound, entries)
	if unbound.keeper.rt != nil {
		t.Fatal("kept without a runtime")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func get(url string) (string, error) {
	c := &http.Client{Timeout: time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestHelperBackend is the backend sealed starts in the tests below, on the
// port SEALED_HELPER_BACKEND names. SEALED_HELPER_MODE: "" answers one
// request, then exits; "serve" serves until killed; "fail" writes an error and
// exits 3; "fork" starts a "serve" child, which stays in the process group
// sealed made for the start command, waits until it answers, and exits.
func TestHelperBackend(t *testing.T) {
	port := os.Getenv("SEALED_HELPER_BACKEND")
	if port == "" {
		return
	}
	switch os.Getenv("SEALED_HELPER_MODE") {
	case "fail":
		fmt.Fprintln(os.Stderr, "boom: no module named server")
		os.Exit(3)
	case "fork":
		child := exec.Command(os.Args[0], "-test.run=^TestHelperBackend$")
		child.Env = append(os.Environ(), "SEALED_HELPER_MODE=serve")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(4)
		}
		for i := 0; i < 200 && !backendAnswers("127.0.0.1:"+port); i++ {
			time.Sleep(25 * time.Millisecond)
		}
		os.Exit(0)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		os.Exit(3)
	}
	fmt.Println("listening on", port)
	served := make(chan struct{})
	var once sync.Once
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pid %d", os.Getpid())
		once.Do(func() { close(served) })
	}))
	if os.Getenv("SEALED_HELPER_MODE") == "serve" {
		select {}
	}
	<-served
	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

// fastSupervision makes the supervisors check and restart within a test.
func fastSupervision(t *testing.T) {
	saved := [3]time.Duration{backendCheckEvery, backendFirstDelay, backendMaxDelay}
	backendCheckEvery, backendFirstDelay, backendMaxDelay = 50*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { backendCheckEvery, backendFirstDelay, backendMaxDelay = saved[0], saved[1], saved[2] })
}

// helperServer is a server whose start commands run TestHelperBackend in mode
// on port; stateFile empty puts the state in a temporary directory.
func helperServer(t *testing.T, port int, mode, stateFile string) (*Server, *ServiceStart) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no test executable path")
	}
	// With the agent account the start command runs as the agent, who cannot
	// enter go test's build directory: run a copy it can.
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "sealed-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	exe = filepath.Join(dir, "helper.test")
	if err := os.WriteFile(exe, b, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if stateFile == "" {
		stateFile = filepath.Join(t.TempDir(), "s.json")
	}
	s := &Server{}
	s.RestoreAgentServices(AgentServiceRuntime{StateFile: stateFile, Binding: "b",
		Env: []string{"SEALED_HELPER_BACKEND=" + strconv.Itoa(port), "SEALED_HELPER_MODE=" + mode}})
	t.Cleanup(s.StopAgentServices)
	return s, &ServiceStart{Command: exe, Args: []string{"-test.run=^TestHelperBackend$"}}
}

func listServices(t *testing.T, s *Server) (out struct {
	Services []ServiceEntry  `json:"services"`
	Backends []BackendStatus `json:"backends"`
}) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleServices(rec, httptest.NewRequest("GET", "/services", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET /services: %v %s", err, rec.Body.String())
	}
	return out
}

func TestBackendStartedAndRestarted(t *testing.T) {
	fastSupervision(t)
	port := freePort(t)
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/api/x"
	s, start := helperServer(t, port, "", "")
	register(t, s, []ServiceEntry{{Path: "/api/x", Method: "GET", Backend: "http://127.0.0.1:" + strconv.Itoa(port), Start: start}})

	var err error
	var first string
	waitFor(t, "the started backend", func() bool { first, err = get(url); return err == nil })
	// That backend exits after one answer; sealed starts it again.
	var second string
	waitFor(t, "the restarted backend", func() bool { second, err = get(url); return err == nil && second != first })

	// Removing the interface stops its backend for good.
	register(t, s, nil)
	if len(s.keeper.sups) != 0 {
		t.Fatal("supervisor left running")
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := get(url); err == nil {
		t.Fatal("backend still answers after its interface was removed")
	}
}

func TestOneBackendForPathsSharingIt(t *testing.T) {
	fastSupervision(t)
	port := freePort(t)
	backend := "http://127.0.0.1:" + strconv.Itoa(port)
	s, start := helperServer(t, port, "serve", "")
	register(t, s, []ServiceEntry{
		{Path: "/api/a", Method: "GET", Backend: backend, Start: start},
		{Path: "/api/b", Method: "GET", Backend: "http://localhost:" + strconv.Itoa(port), Start: start},
	})
	waitFor(t, "the backend", func() bool { _, err := get(backend + "/api/a"); return err == nil })
	got := listServices(t, s).Backends
	if len(s.keeper.sups) != 1 || len(got) != 1 || len(got[0].Paths) != 2 || got[0].Starts != 1 || got[0].State != backendRunning {
		t.Fatalf("one backend, two paths, one start expected: %+v", got)
	}
}

func TestBackendOutputAndExitShown(t *testing.T) {
	fastSupervision(t)
	port := freePort(t)
	s, start := helperServer(t, port, "fail", "")
	register(t, s, []ServiceEntry{{Path: "/api/x", Method: "GET", Backend: "http://127.0.0.1:" + strconv.Itoa(port), Start: start}})
	waitFor(t, "the failure shown", func() bool {
		b := listServices(t, s).Backends
		return len(b) == 1 && b[0].LastExit == "exit status 3" && strings.Contains(b[0].Output, "boom: no module named server")
	})
}

func TestBackendKeptWhenTheListCannotBeWritten(t *testing.T) {
	fastSupervision(t)
	port := freePort(t)
	backend := "http://127.0.0.1:" + strconv.Itoa(port)
	s, start := helperServer(t, port, "serve", filepath.Join(t.TempDir(), "missing", "s.json"))
	if got := register(t, s, []ServiceEntry{{Path: "/api/x", Method: "GET", Backend: backend, Start: start}}); got["warning"] == nil {
		t.Fatal("no warning that the list is not kept")
	}
	waitFor(t, "the backend", func() bool { _, err := get(backend + "/api/x"); return err == nil })
}

func TestServerForkedByTheStartCommandStoppedWithIt(t *testing.T) {
	fastSupervision(t)
	port := freePort(t)
	backend := "http://127.0.0.1:" + strconv.Itoa(port)
	s, start := helperServer(t, port, "fork", "")
	register(t, s, []ServiceEntry{{Path: "/api/x", Method: "GET", Backend: backend, Start: start}})
	waitFor(t, "the forked server", func() bool {
		b := listServices(t, s).Backends
		return len(b) == 1 && b[0].State == backendAnswering
	})
	register(t, s, nil)
	waitFor(t, "the forked server stopped", func() bool { _, err := get(backend + "/api/x"); return err != nil })
}

func TestBackendLeftToTheAgentWhileItAnswers(t *testing.T) {
	saved := backendCheckEvery
	backendCheckEvery = 50 * time.Millisecond
	t.Cleanup(func() { backendCheckEvery = saved })
	// Something (the agent's own process) already serves the port: sealed
	// starts nothing, even with a start command that would fail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "agent's own") }))
	defer srv.Close()
	s := &Server{}
	s.RestoreAgentServices(AgentServiceRuntime{StateFile: filepath.Join(t.TempDir(), "s.json"), Binding: "b"})
	t.Cleanup(s.StopAgentServices)
	register(t, s, []ServiceEntry{{Path: "/api/y", Method: "GET", Backend: srv.URL, Start: &ServiceStart{Command: "/nonexistent/backend"}}})
	time.Sleep(300 * time.Millisecond)
	if body, err := get(srv.URL + "/api/y"); err != nil || body != "agent's own" {
		t.Fatalf("agent's backend disturbed: %q %v", body, err)
	}
}

func TestHelloServiceListKinds(t *testing.T) {
	s := &Server{services: []ServiceEntry{{Path: "/api/report", Method: "GET", Backend: "http://127.0.0.1:8090",
		Start: &ServiceStart{Command: "python3", Args: []string{"server.py"}}}}}
	got := s.helloServiceList()
	if len(got) != 2 || got[0].Kind != report.ServiceKindRuntime || got[1].Kind != report.ServiceKindAgent {
		t.Fatalf("kinds: %+v", got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "server.py") || strings.Contains(string(b), "8090") {
		t.Fatalf("/hello shows the start command or backend: %s", b)
	}
}
