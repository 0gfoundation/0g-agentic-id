package servicehost

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func newTestManager(base, binding string) (*Manager, error) {
	return NewWithOptions(base, binding, Options{SkipResourceLimitsForTests: true})
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
	m, err := newTestManager(dir, "owner:identity")
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
	reloaded, err := newTestManager(dir, "owner:identity")
	if err != nil || reloaded.List()[0].Version != next.Version {
		t.Fatalf("reload: %v", err)
	}
	if _, err := newTestManager(dir, "another-owner:identity"); err == nil {
		t.Fatal("resumed another owner's services")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := newTestManager(filepath.Join(dir, "link"), "owner:identity"); err == nil {
		t.Fatal("followed symlink")
	}
}

func TestSandboxLifecycleAndIsolation(t *testing.T) {
	root(t)
	if os.Getenv("SEALED_SERVICE_TESTS") != "1" {
		t.Skip("set SEALED_SERVICE_TESTS=1 in a namespace-capable container")
	}
	t.Setenv("SERVICE_TEST_SECRET", "not-for-the-child")
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, id := range []string{"first", "second"} {
		if _, err = m.Publish(manifest(id, requestFixture)); err != nil {
			t.Fatal(err)
		}
		if _, err = m.Start(id); err != nil {
			t.Fatal(err)
		}
	}
	assertNoWorkers := func(m *Manager) {
		t.Helper()
		m.mu.Lock()
		defer m.mu.Unlock()
		if len(m.workers) != 0 {
			t.Fatal("service enablement or completed request left a worker running")
		}
	}
	assertNoWorkers(m)
	check := func(m *Manager, id string) {
		t.Helper()
		resp, err := m.HTTPClient(id).Do(taskRequest(context.Background(), id, 0, testServiceVersion(m, id)))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("request: %s %v", b, err)
		}
		for _, want := range []string{`"owner_home": false`, `"sign_socket": false`, `"sealed_state": false`, `"secret": null`, `"readonly": true`, `"fresh": true`} {
			if !strings.Contains(string(b), want) {
				t.Fatalf("isolation missing %s: %s", want, b)
			}
		}
		assertNoWorkers(m)
	}
	check(m, "first")
	check(m, "second")
	if _, err = m.Publish(manifest("first", "changed")); err == nil {
		t.Fatal("updated an enabled service")
	}
	if _, err = m.Stop("first"); err != nil {
		t.Fatal(err)
	}
	resp, err := m.HTTPClient("first").Do(taskRequest(context.Background(), "first", 0, testServiceVersion(m, "first")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatal("stopped service admitted a request")
	}
	check(m, "second")
	// Reboot restores admission only. Neither work nor processes survive.
	m.Close()
	restored, err := newTestManager(m.base, "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restored.Resume()
	assertNoWorkers(restored)
	for _, s := range restored.List() {
		if s.ID == "first" && (s.State != "stopped" || s.Desired) {
			t.Fatal("reboot enabled a stopped service")
		}
		if s.ID == "second" && s.State != "running" {
			t.Fatal("reboot did not restore admission")
		}
	}
	check(restored, "second")
	if _, err := os.Stat(filepath.Join(m.programs, "second", "work")); !os.IsNotExist(err) {
		t.Fatal("service has a persistent working directory")
	}
}
