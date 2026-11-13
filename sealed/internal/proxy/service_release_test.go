package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"seal-verify/internal/servicehost"
)

func TestPublishedReleaseIsSignedWithoutInvokingStoppedProgram(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned service publication")
	}
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(500) }))
	defer backend.Close()
	host, err := servicehost.New(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	status, err := host.Publish(servicehost.Manifest{ID: "audit", Command: "python3", Args: []string{"/app/main.py"}, Files: []servicehost.File{{Path: "main.py", Data: base64.StdEncoding.EncodeToString([]byte("print('public source')"))}}})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := armedProxy(t, backend.URL, testValidator)
	s.SetAdapter(servicePolicyAdapter{name: "0g-harness"})
	s.SetServiceHost(host)
	out := httptest.NewRecorder()
	s.handleProxy(out, httptest.NewRequest("GET", "/api/mcp/audit?sealed-release=1", nil))
	if out.Code != 200 || out.Header().Get("X-Agent-Proof") == "" || out.Header().Get("Cache-Control") != "no-store" || called {
		t.Fatalf("audit bypassed root signing or invoked program: %d %s", out.Code, out.Body.String())
	}
	var release servicehost.PublishedRelease
	if json.Unmarshal(out.Body.Bytes(), &release) != nil {
		t.Fatal("invalid release JSON")
	}
	hash := sha256.Sum256(release.CanonicalManifest)
	if release.Version != status.Version || hex.EncodeToString(hash[:]) != status.Version || release.Manifest.ID != "audit" {
		t.Fatal("audit release lost immutable code binding")
	}
	for _, tc := range []struct {
		method, path string
		private      bool
	}{
		{"POST", "/api/mcp/audit?sealed-release=1", false},
		{"GET", "/api/mcp/audit?sealed-release=0", false},
		{"GET", "/api/mcp/audit?sealed-release=1&sealed-release=1", false},
		{"GET", "/api/mcp/audit?sealed-release=1", true},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.private {
			req.Header.Set(servicehost.RuntimeInputHeader, "e30=")
		}
		out = httptest.NewRecorder()
		s.handleProxy(out, req)
		if out.Code != 400 || called {
			t.Fatalf("invalid audit request reached program: %d", out.Code)
		}
	}
	out = httptest.NewRecorder()
	s.handleProxy(out, httptest.NewRequest("GET", "/api/mcp/audit/child?sealed-release=1", strings.NewReader("")))
	if out.Code != 404 || called {
		t.Fatal("audit accepted a non-exact service path")
	}
}

type blockedReleaseWriter struct {
	header  http.Header
	entered chan struct{}
	unblock <-chan struct{}
	once    sync.Once
}

func (w *blockedReleaseWriter) Header() http.Header { return w.header }
func (w *blockedReleaseWriter) WriteHeader(int)     {}
func (w *blockedReleaseWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.unblock
	return len(p), nil
}

func TestReleaseAuditConcurrencyIncludesSlowResponseWrites(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned service publication")
	}
	host, err := servicehost.New(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if _, err := host.Publish(servicehost.Manifest{ID: "audit", Command: "python3", Args: []string{"/app/main.py"}, Files: []servicehost.File{{Path: "main.py", Data: base64.StdEncoding.EncodeToString([]byte("print('public source')"))}}}); err != nil {
		t.Fatal(err)
	}
	s, _ := armedProxy(t, "http://localhost", testValidator)
	s.SetAdapter(servicePolicyAdapter{name: "0g-harness"})
	s.SetServiceHost(host)
	unblock := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(unblock) }) }
	defer release()
	done := make(chan struct{}, 2)
	for range 2 {
		writer := &blockedReleaseWriter{header: make(http.Header), entered: make(chan struct{}), unblock: unblock}
		go func() {
			s.handleProxy(writer, httptest.NewRequest("GET", "/api/mcp/audit?sealed-release=1", nil))
			done <- struct{}{}
		}()
		select {
		case <-writer.entered:
		case <-time.After(time.Second):
			t.Fatal("audit write did not begin")
		}
	}
	out := httptest.NewRecorder()
	s.handleProxy(out, httptest.NewRequest("GET", "/api/mcp/audit?sealed-release=1", nil))
	if out.Code != 503 || !strings.Contains(out.Body.String(), "concurrency") {
		t.Fatal("parallel audit snapshots exceeded process limit")
	}
	release()
	for range 2 {
		<-done
	}
}
