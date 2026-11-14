package servicehost

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"seal-verify/internal/serviceidentity"
	"seal-verify/internal/servicesandbox"
)

func TestDiskUsageCountsAllocatedBlocksAndFollowsNoLink(t *testing.T) {
	dir := t.TempDir()
	// A sparse file occupies almost nothing whatever its size; written data
	// counts in full.
	sparse, err := os.Create(filepath.Join(dir, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sparse.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	sparse.Close()
	if err := os.WriteFile(filepath.Join(dir, "data"), make([]byte, 1<<20), 0600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "big"), make([]byte, 4<<20), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	got := diskUsage([]string{dir}, 1<<40)
	if got < 1<<20 || got > 2<<20 {
		t.Fatalf("usage %d, want about 1 MiB", got)
	}
	// A tree deeper than the walk descends counts as over any limit.
	deep := t.TempDir()
	path := deep
	for range maxWalkDepth + 2 {
		path = filepath.Join(path, "d")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if got := diskUsage([]string{deep}, 1<<40); got <= 1<<40 {
		t.Fatalf("deep tree counted %d", got)
	}
}

func TestNodeNeedsSixteenProcesses(t *testing.T) {
	m := manifest("demo", "x")
	m.Command, m.Processes = "node", minNodeProcesses-1
	if _, err := m.normalize(); err == nil {
		t.Fatal("accepted node with too few processes")
	}
	m.Processes = minNodeProcesses
	if _, err := m.normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessBudgetRefusesRequests(t *testing.T) {
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
	m.mu.Lock()
	m.workers[1] = &worker{service: "other", processes: MaxServiceProcesses - 63}
	m.mu.Unlock()
	resp, err := m.HTTPClient("task").Do(taskRequest(context.Background(), "x", 0, testServiceVersion(m, "task")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want the process budget's 503", resp.StatusCode)
	}
	m.mu.Lock()
	delete(m.workers, 1)
	m.mu.Unlock()
}

func TestPublishWaitsForCoordinatorCleanup(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Publish(manifest("task", "v1")); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.entries["task"].controller = &coordinator{}
	m.mu.Unlock()
	if _, err := m.Publish(manifest("task", "v2")); err == nil || !strings.Contains(err.Error(), "still being cleaned up") {
		t.Fatalf("published over a coordinator being cleaned up: %v", err)
	}
	m.mu.Lock()
	m.entries["task"].controller = nil
	m.mu.Unlock()
}

func TestDiscardDirReturnsBeforeRemoval(t *testing.T) {
	root(t)
	dir := filepath.Join(t.TempDir(), "tmp")
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := discardDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory still in place: %v", err)
	}
	if err := discardDir(dir); err != nil {
		t.Fatalf("missing directory: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		left, _ := filepath.Glob(dir + ".discard-*")
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("discarded directories remain: %v", left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A previous sealed may leave processes of service identities behind; a new
// manager must not hand identities out while they live. Needs the launcher.
func TestLeftoverIdentitiesAreReaped(t *testing.T) {
	root(t)
	if os.Getenv("SEALED_SERVICE_TESTS") != "1" {
		t.Skip("set SEALED_SERVICE_TESTS=1 as root with sealed-service-launcher installed")
	}
	uid := uint32(serviceidentity.Base + 99)
	leftover := exec.Command("/bin/sh", "-c", "sleep 300 & sleep 300")
	leftover.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	if err := leftover.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = leftover.Wait() }()
	time.Sleep(200 * time.Millisecond)
	if n := servicesandbox.Scan(map[uint32]bool{uid: true})[uid].Processes; n < 2 {
		t.Fatalf("fixture started %d processes", n)
	}
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if n := servicesandbox.Scan(map[uint32]bool{uid: true})[uid].Processes; n != 0 {
		t.Fatalf("%d leftover processes survived the new manager", n)
	}
}
