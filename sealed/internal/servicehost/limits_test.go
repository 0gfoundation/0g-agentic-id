package servicehost

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"seal-verify/internal/inferproxy"
	"seal-verify/internal/privsep"
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

// Sockets a service binds and closes stay as directory entries; each counts
// at least one block, so a run directory cannot pile up inodes unseen.
func TestDiskUsageCountsSocketEntries(t *testing.T) {
	dir := t.TempDir()
	for i := range 64 {
		ln, err := net.Listen("unix", filepath.Join(dir, fmt.Sprintf("s%d", i)))
		if err != nil {
			t.Skipf("cannot bind a unix socket here: %v", err)
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		ln.Close()
	}
	if got := diskUsage([]string{dir}, 1<<40); got < 64*4096 {
		t.Fatalf("64 socket entries counted %d bytes", got)
	}
}

// Every socket path sealed binds or hands a service must fit a Unix socket
// address (107 bytes and a NUL) with the longest service id and identity.
func TestSocketPathsFit(t *testing.T) {
	programID := sha256.Sum256([]byte("/any/services/base"))
	m := &Manager{programs: fmt.Sprintf("/var/lib/sealed-service-programs/%x", programID[:8])}
	coordinator := m.coordinatorRunDir(serviceidentity.Base + serviceidentity.Count - 1)
	task := filepath.Join(m.programs, taskDirName, "e-4294967295", "run") // os.MkdirTemp's longest suffix
	for _, dir := range []string{coordinator, task} {
		for _, name := range []string{"service.sock", "control.sock", "egress.sock", "model.sock"} {
			if p := filepath.Join(dir, name); len(p) > 107 {
				t.Errorf("%s is %d bytes", p, len(p))
			}
		}
	}
}

func TestPublishRulesApplyToNewReleasesOnly(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*Manifest)
		ok   bool
	}{
		{"node with too few processes", func(m *Manifest) { m.Command, m.Processes = "node", minNodeProcesses-1 }, false},
		{"node worker with too few processes", func(m *Manifest) {
			m.Worker, m.Processes = &Program{Command: "node", Args: []string{"w.mjs"}}, minNodeProcesses-1
		}, false},
		{"node with enough processes", func(m *Manifest) {
			m.Command, m.Worker, m.Processes = "node", &Program{Command: "node", Args: []string{"w.mjs"}}, minNodeProcesses
		}, true},
		{"egress host too long", func(m *Manifest) {
			m.Network, m.EgressHosts = "egress", []string{strings.Repeat("a", maxHostLength-4) + ".com" + "x:443"}
		}, false},
		{"longest egress host", func(m *Manifest) {
			m.Network, m.EgressHosts = "egress", []string{strings.Repeat("a", maxHostLength-4) + ".com:443"}
		}, true},
	} {
		m := manifest("demo", "x")
		c.edit(&m)
		if _, err := m.normalize(); err != nil {
			t.Fatalf("%s: normalize: %v", c.name, err)
		}
		if err := m.checkPublish(); (err == nil) != c.ok {
			t.Errorf("%s: checkPublish %v", c.name, err)
		}
	}
	// A release saved before these rules still loads.
	root(t)
	base := filepath.Join(t.TempDir(), "services")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := manifest("legacy", "x")
	legacy.Command, legacy.Processes = "node", 8
	v, err := legacy.normalize()
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := json.Marshal(map[string]any{"binding": "owner:identity", "entries": []*entry{{Manifest: legacy, Status: Status{ID: "legacy", Version: v}}}})
	if err := os.WriteFile(filepath.Join(base, "registry.json"), saved, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := newTestManager(base, "owner:identity")
	if err != nil {
		t.Fatalf("a saved release failed to load: %v", err)
	}
	defer m.Close()
	if _, ok := m.Match("/api/mcp/legacy"); !ok {
		t.Fatal("saved release missing")
	}
}

// The largest saved execution record, with a receipt as large as the
// Harness accepts, stays within the record cap that restore reads.
func TestLargestExecutionRecordFits(t *testing.T) {
	man := manifest("abcdefghijklmnopqrstuvwxyz012345", "x")
	man.Network = "egress"
	for i := range 32 {
		man.EgressHosts = append(man.EgressHosts, fmt.Sprintf("%0*d.example:65535", maxHostLength-8, i))
	}
	man.InferenceBudget = &inferproxy.TaskLimits{Calls: 64, InputBytes: 16 << 20, OutputTokens: 8192}
	if _, err := man.normalize(); err != nil {
		t.Fatal(err)
	}
	code := -2147483648
	status := ExecutionStatus{Handle: strings.Repeat("h", 64), Service: man.ID, Key: "1234567890123-" + strings.Repeat("k", 48), Version: strings.Repeat("v", 64),
		InputHash: strings.Repeat("i", 64), State: "quarantined", StartedAt: 1 << 62, Deadline: 1 << 62, FinishedAt: 1 << 62, ExitCode: &code,
		Reason: "resource_cleanup_failed", OutputBytes: MaxExecutionOutput, OutputHash: strings.Repeat("o", 64), OutputAvailable: true, UID: 64999,
		Receipt: strings.Repeat("r", 16<<10)}
	isolation := landlockProfile(man)
	isolation.WorkerRuntimeHash = strings.Repeat("w", 64)
	b, err := json.Marshal(executionRecord{"0x" + strings.Repeat("a", 40) + ":" + strings.Repeat("s", 64), status, isolation})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > maxExecutionRecordBytes {
		t.Fatalf("largest record is %d bytes, cap %d", len(b), maxExecutionRecordBytes)
	}
	t.Logf("largest record: %d bytes", len(b))
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
	done := make(chan struct{})
	close(done)
	m.mu.Lock()
	m.workers[1] = &worker{service: "other", processes: MaxServiceProcesses - 63, cancel: func() {}, done: done}
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

func closedController() *coordinator {
	done := make(chan struct{})
	close(done)
	return &coordinator{cancel: func() {}, done: done}
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
	m.entries["task"].controller = closedController()
	m.mu.Unlock()
	if _, err := m.Publish(manifest("task", "v2")); err == nil || !strings.Contains(err.Error(), "still being cleaned up") {
		t.Fatalf("published over a coordinator being cleaned up: %v", err)
	}
	m.mu.Lock()
	m.entries["task"].controller = nil
	m.mu.Unlock()
}

// Resume leaves alone a coordinator the owner started before it.
func TestResumeKeepsARunningCoordinator(t *testing.T) {
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
	e := m.entries["task"]
	e.Desired, e.State, e.controller = true, "running", closedController()
	m.mu.Unlock()
	m.Resume()
	m.mu.Lock()
	state := e.State
	e.controller = nil
	m.mu.Unlock()
	if state != "running" {
		t.Fatalf("Resume set a running coordinator to %q", state)
	}
}

// A coordinator that cannot start (here: its identity is quarantined) stays
// wanted and is retried; the retry reports the next cause.
func TestCoordinatorStartIsRetried(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	man := manifest("task", "x")
	man.Worker = &Program{Command: "python3", Args: []string{"w.py"}}
	if _, err := m.Publish(man); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	uid := m.entries["task"].ControllerUID
	m.quarantined[uid] = "fixture"
	m.mu.Unlock()
	if _, err := m.Start("task"); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("start of a quarantined coordinator: %v", err)
	}
	m.mu.Lock()
	state := m.entries["task"].State
	delete(m.quarantined, uid)
	m.mu.Unlock()
	if state != "restarting" {
		t.Fatalf("state %q, want restarting", state)
	}
	deadline := time.Now().Add(minRestartDelay + 3*time.Second)
	for {
		m.mu.Lock()
		e := m.entries["task"]
		retried := !strings.Contains(e.Error, "quarantined") || e.controller != nil
		m.mu.Unlock()
		if retried {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the coordinator start was not retried")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRestartDelayBacksOffAndResets(t *testing.T) {
	for _, c := range []struct{ prev, uptime, want time.Duration }{
		{0, time.Second, minRestartDelay},
		{minRestartDelay, time.Second, 2 * minRestartDelay},
		{40 * time.Second, time.Second, maxRestartDelay},
		{maxRestartDelay, time.Second, maxRestartDelay},
		{maxRestartDelay, stableCoordinator, minRestartDelay},
	} {
		if got := nextRestartDelay(c.prev, c.uptime); got != c.want {
			t.Errorf("nextRestartDelay(%v, %v) = %v, want %v", c.prev, c.uptime, got, c.want)
		}
	}
}

// Stop reports "stopping" when processes outlive its wait, and "stopped"
// once they are gone.
func TestStoppingClearsWhenProcessesExit(t *testing.T) {
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
	old := stopWait
	stopWait = 50 * time.Millisecond
	defer func() { stopWait = old }()
	done := make(chan struct{})
	m.mu.Lock()
	m.workers[1] = &worker{service: "task", cancel: func() {}, done: done}
	m.mu.Unlock()
	s, err := m.Stop("task")
	if err != nil || s.State != "stopping" {
		t.Fatalf("Stop: %+v %v", s, err)
	}
	m.mu.Lock()
	delete(m.workers, 1)
	m.mu.Unlock()
	close(done)
	deadline := time.Now().Add(3 * time.Second)
	for {
		m.mu.Lock()
		state, msg := m.entries["task"].State, m.entries["task"].Error
		m.mu.Unlock()
		if state == "stopped" && msg == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %q (%q) after the processes exited", state, msg)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDiscardDirReturnsBeforeRemoval(t *testing.T) {
	root(t)
	dir := filepath.Join(t.TempDir(), "tmp")
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0700); err != nil {
		t.Fatal(err)
	}
	var queued []string
	old := removeInBackground
	removeInBackground = func(p string) { queued = append(queued, p) }
	defer func() { removeInBackground = old }()
	if err := discardDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory still in place: %v", err)
	}
	// The removal was only queued: the moved tree is still whole.
	if len(queued) != 1 || !strings.HasPrefix(queued[0], dir+".discard-") {
		t.Fatalf("queued removals %v", queued)
	}
	if _, err := os.Lstat(filepath.Join(queued[0], "a", "b")); err != nil {
		t.Fatalf("discarded tree was removed before discardDir returned: %v", err)
	}
	if err := discardDir(dir); err != nil {
		t.Fatalf("missing directory: %v", err)
	}
	// A later discard sweeps what an earlier one left.
	if len(queued) != 2 || queued[1] != queued[0] {
		t.Fatalf("queued removals %v", queued)
	}
	if err := privsep.RemoveAll(queued[0]); err != nil {
		t.Fatal(err)
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
	// Production options: the startup reap runs (test managers skip it).
	m, err := NewWithOptions(filepath.Join(t.TempDir(), "services"), "owner:identity", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if n := servicesandbox.Scan(map[uint32]bool{uid: true})[uid].Processes; n != 0 {
		t.Fatalf("%d leftover processes survived the new manager", n)
	}
	if len(m.quarantined) != 0 {
		t.Fatalf("quarantined %v", m.quarantined)
	}
}

// The process-control "capabilities" action tells a coordinator, before it
// charges anyone, whether an execution that exits 0 would receive a receipt.
func TestCapabilitiesReportReceiptReadiness(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	h := m.ExecutionHandler("svc")
	ask := func(body string) (int, string) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/executions", strings.NewReader(body)))
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	if code, body := ask(`{"action":"capabilities"}`); code != 200 || body != `{"launch":true,"receipts":false}` {
		t.Fatalf("without an attestor: %d %s", code, body)
	}
	ready := true
	m.SetExecutionAttestor(func(ExecutionStatus, IsolationProfile) (string, error) { return "receipt", nil })
	m.SetReceiptCapability(func() bool { return ready })
	if code, body := ask(`{"action":"capabilities"}`); code != 200 || body != `{"launch":true,"receipts":true}` {
		t.Fatalf("ready: %d %s", code, body)
	}
	ready = false
	if code, body := ask(`{"action":"capabilities"}`); code != 200 || body != `{"launch":true,"receipts":false}` {
		t.Fatalf("not ready: %d %s", code, body)
	}
	if code, _ := ask(`{"action":"capabilities","key":"1234567890123-abcdefghijklmnop"}`); code != 400 {
		t.Fatalf("capabilities accepted an argument: %d", code)
	}
}

// A coordinator that ends because it is no longer wanted leaves its service
// stopped, with no "still being cleaned up" error behind.
func TestCoordinatorStopClearsCleanupError(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	man := manifest("coord", "x")
	man.Worker = &Program{Command: "python3", Args: []string{"server.py"}}
	if _, err := m.Publish(man); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := &isolatedCommand{Cmd: exec.Command("/bin/sh", "-c", "exit 0"), cleanupResource: func(context.Context) error { return nil }}
	c := &coordinator{cancel: cancel, done: make(chan struct{}), server: &http.Server{}, cmd: cmd, started: time.Now()}
	m.mu.Lock()
	e := m.entries["coord"]
	e.Desired, e.State, e.Error = false, "stopping", "processes are still being cleaned up"
	e.controller = c
	gen := e.generation
	m.mu.Unlock()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	m.superviseCoordinator(ctx, e, c, gen)
	m.mu.Lock()
	state, msg, held := e.State, e.Error, e.controller
	m.mu.Unlock()
	if state != "stopped" || msg != "" || held != nil {
		t.Fatalf("after the coordinator ended: state %q error %q controller %v", state, msg, held != nil)
	}
}

// The memory check keeps its cadence while a disk walk is slow.
func TestSlowDiskWalkDoesNotDelayMemoryCheck(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	w := newResourceWatcher(stop, "")
	w.memTick, w.dskTick = 20*time.Millisecond, 20*time.Millisecond
	w.walk = func([]string, int64) int64 { time.Sleep(5 * time.Second); return 0 }
	w.scan = func(uids map[uint32]bool) map[uint32]servicesandbox.Usage {
		out := map[uint32]servicesandbox.Usage{}
		for uid := range uids {
			out[uid] = servicesandbox.Usage{RSSBytes: 1 << 30}
		}
		return out
	}
	limited := make(chan string, 1)
	c := &isolatedCommand{Cmd: &exec.Cmd{}, uid: 20042, limits: limits{residentBytes: 1 << 20, diskBytes: 1 << 20, diskDirs: []string{"/nonexistent"}},
		onLimit: func(reason string) { limited <- reason }}
	w.add(c)
	select {
	case reason := <-limited:
		if reason != "memory_limit" {
			t.Fatalf("stopped for %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("a slow disk walk delayed the memory check")
	}
}

// One-shot request workers cannot take the slots executions need.
func TestRequestWorkersLeaveRoomForExecutions(t *testing.T) {
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
	try := func() int {
		resp, err := m.HTTPClient("task").Do(taskRequest(context.Background(), "x", 0, testServiceVersion(m, "task")))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	m.mu.Lock()
	for i := range MaxRequestWorkers {
		m.workers[uint32(1+i)] = &worker{service: "other", cancel: func() {}, done: make(chan struct{}), processes: 1, request: true}
	}
	m.mu.Unlock()
	if code := try(); code != http.StatusServiceUnavailable {
		t.Fatalf("a request worker beyond its share got %d", code)
	}
	m.mu.Lock()
	for i := range MaxRequestWorkers {
		delete(m.workers, uint32(1+i))
	}
	m.workers[1] = &worker{service: "other", cancel: func() {}, done: make(chan struct{}), processes: MaxRequestProcesses - 10, request: true}
	m.mu.Unlock()
	if code := try(); code != http.StatusServiceUnavailable {
		t.Fatalf("request workers beyond their process share got %d", code)
	}
	m.mu.Lock()
	delete(m.workers, 1)
	m.mu.Unlock()
}

// launch is false whenever sealed's own preparation for a service process
// would fail now: low free space, or the verified runtime unavailable.
func TestCapabilitiesReportLaunchReadiness(t *testing.T) {
	root(t)
	runtimeErr := error(nil)
	m, err := NewWithOptions(filepath.Join(t.TempDir(), "services"), "owner:identity", Options{SkipResourceLimitsForTests: true,
		AcquireRuntime: func(context.Context) (RuntimeLease, error) {
			if runtimeErr != nil {
				return RuntimeLease{}, runtimeErr
			}
			hash := strings.Repeat("c", 64)
			return RuntimeLease{Hash: hash, Dir: "/opt/0g-harness/" + hash, Release: func() {}}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !m.LaunchAvailable() {
		t.Fatal("launch unavailable on a ready manager")
	}
	old := diskLowCheck
	diskLowCheck = func(string) bool { return true }
	low := m.LaunchAvailable()
	diskLowCheck = old
	if low {
		t.Fatal("launch available with low free space")
	}
	runtimeErr = fmt.Errorf("runtime listing unavailable")
	if m.LaunchAvailable() {
		t.Fatal("launch available without the verified runtime")
	}
}

// A temporary file a crash left between write and rename, or a corrupt
// record, never disables hosting: the temporary file is removed, the record
// set aside, and the manager starts.
func TestRestoreSurvivesLeftoverAndCorruptRecords(t *testing.T) {
	root(t)
	base := filepath.Join(t.TempDir(), "services")
	m, err := newTestManager(base, "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	dir := filepath.Join(base, "executions")
	handle := strings.Repeat("ab", 32)
	tmp := "." + handle + ".json.sealed-tmp-0123456789ab"
	for name, data := range map[string]string{tmp: "{\"partial", handle + ".json": "not json", "notes.txt": "x"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err = newTestManager(base, "owner:identity")
	if err != nil {
		t.Fatalf("one bad file disabled hosting: %v", err)
	}
	defer m.Close()
	if _, err := os.Lstat(filepath.Join(dir, tmp)); !os.IsNotExist(err) {
		t.Fatalf("leftover temporary file kept: %v", err)
	}
	for _, name := range []string{handle + ".json", "notes.txt"} {
		if _, err := os.Lstat(filepath.Join(dir, ".bad-"+name)); err != nil {
			t.Fatalf("%s not set aside: %v", name, err)
		}
	}
	if len(m.executions) != 0 {
		t.Fatalf("restored %d records from bad files", len(m.executions))
	}
}

// The reservation is synced outside the manager lock; a spawn of the same key
// meanwhile sees the reservation, and a failed sync leaves the key's
// tombstone as never ran.
func TestReservationSyncsOutsideTheLock(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	man := manifest("paid", "x")
	man.Worker = &Program{Command: "python3", Args: []string{"server.py"}}
	if _, err := m.Publish(man); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.entries["paid"].Desired = true // admission only; no coordinator is needed here
	m.mu.Unlock()
	old := syncRecord
	defer func() { syncRecord = old }()
	entered, release := make(chan struct{}), make(chan struct{})
	syncRecord = func(string, []byte, os.FileMode) error {
		close(entered)
		<-release
		return fmt.Errorf("disk failed")
	}
	key := fmt.Sprintf("%d-%s", time.Now().UnixMilli(), strings.Repeat("k", 20))
	first := make(chan error, 1)
	go func() {
		_, err := m.SpawnExecution("paid", key, []byte("{}"), nil)
		first <- err
	}()
	<-entered
	// The lock is free while the sync runs, and the key is already taken.
	done := make(chan struct{})
	var dup ExecutionStatus
	var dupErr error
	go func() {
		dup, dupErr = m.SpawnExecution("paid", key, []byte("{}"), nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a duplicate spawn waited on the reservation sync")
	}
	if dupErr != nil || dup.State != "starting" {
		t.Fatalf("duplicate during the sync: %+v %v", dup, dupErr)
	}
	m.List() // the manager lock is not held by the sync
	close(release)
	if err := <-first; err == nil {
		t.Fatal("a failed reservation sync started the execution")
	}
	status, err := m.FindExecution("paid", key)
	if err != nil || status.State != "failed" || status.Reason != "start_failed" || status.ExitCode != nil {
		t.Fatalf("tombstone after a failed sync: %+v %v", status, err)
	}
	again, err := m.SpawnExecution("paid", key, []byte("{}"), nil)
	if err != nil || again.Handle != status.Handle || again.State != "failed" {
		t.Fatalf("a retry of the key ran again: %+v %v", again, err)
	}
	m.mu.Lock()
	_, held := m.workers[status.UID]
	m.mu.Unlock()
	if held {
		t.Fatal("the identity of a failed reservation stays held")
	}
}

// A record outlives its key's acceptance window even when it finished long
// ago: a key issued up to 30 s ahead is accepted until ten minutes after its
// issue time, and its record is the tombstone that keeps it from running again.
func TestRecordOutlivesItsKeyWindow(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	now := time.Now()
	future := fmt.Sprintf("%d-%s", now.Add(25*time.Second).UnixMilli(), strings.Repeat("f", 20))
	stale := fmt.Sprintf("%d-%s", now.Add(-11*time.Minute).UnixMilli(), strings.Repeat("s", 20))
	finished := now.Add(-executionRetention - time.Second).UnixMilli()
	m.mu.Lock()
	for i, key := range []string{future, stale} {
		h := strings.Repeat(fmt.Sprintf("%x", i+1), 64)
		m.executions[h] = &execution{ExecutionStatus: ExecutionStatus{Handle: h, Service: "svc", Key: key, State: "exited", FinishedAt: finished}, done: make(chan struct{})}
		m.executionKeys[executionKey("svc", key)] = h
	}
	m.pruneExecutionsLocked()
	_, keptFuture := m.executionKeys[executionKey("svc", future)]
	_, keptStale := m.executionKeys[executionKey("svc", stale)]
	m.mu.Unlock()
	if !keptFuture {
		t.Fatal("pruned the tombstone of a key that can still be accepted")
	}
	if keptStale {
		t.Fatal("kept a record past both windows")
	}
}
