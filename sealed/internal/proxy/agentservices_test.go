package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/privsep"
	"seal-verify/internal/report"
)

func TestValidateStart(t *testing.T) {
	home := privsep.AgentHome()
	ok := []*ServiceStart{nil, {Command: "python3", Args: []string{"server.py"}}, {Command: "node", Dir: home}, {Command: "node", Dir: home + "/site"}}
	for _, s := range ok {
		if err := validateStart(s); err != nil {
			t.Errorf("%+v refused: %v", s, err)
		}
	}
	bad := []*ServiceStart{
		{Command: ""},
		{Command: "a\x00b"},
		{Command: strings.Repeat("a", maxStartCommand+1)},
		{Command: "node", Args: make([]string, maxStartArgs+1)},
		{Command: "node", Args: []string{"a\x00"}},
		{Command: "node", Dir: "site"},
		{Command: "node", Dir: "/etc"},
		{Command: "node", Dir: home + "/../etc"},
		{Command: "node", Dir: home + "x"},
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

// TestHelperBackend is the backend sealed starts in
// TestBackendStartedAndRestarted: it answers one request, then exits.
func TestHelperBackend(t *testing.T) {
	port := os.Getenv("SEALED_HELPER_BACKEND")
	if port == "" {
		return
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		os.Exit(3)
	}
	served := make(chan struct{})
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pid %d", os.Getpid())
		close(served)
	}))
	<-served
	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

func TestBackendStartedAndRestarted(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no test executable path")
	}
	saved := [3]time.Duration{backendCheckEvery, backendFirstDelay, backendMaxDelay}
	backendCheckEvery, backendFirstDelay, backendMaxDelay = 50*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { backendCheckEvery, backendFirstDelay, backendMaxDelay = saved[0], saved[1], saved[2] })

	port := freePort(t)
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/api/x"
	s := &Server{}
	s.RestoreAgentServices(AgentServiceRuntime{StateFile: filepath.Join(t.TempDir(), "s.json"), Binding: "b", Env: []string{"SEALED_HELPER_BACKEND=" + strconv.Itoa(port)}})
	t.Cleanup(s.StopAgentServices)
	register(t, s, []ServiceEntry{{Path: "/api/x", Method: "GET", Backend: "http://127.0.0.1:" + strconv.Itoa(port),
		Start: &ServiceStart{Command: exe, Args: []string{"-test.run=^TestHelperBackend$"}}}})

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
