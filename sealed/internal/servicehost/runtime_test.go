package servicehost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func cleanupFailureFixture(cmd *exec.Cmd) (*isolatedCommand, chan struct{}, <-chan struct{}, *atomic.Int32) {
	allow := make(chan struct{})
	released := make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	c := &isolatedCommand{Cmd: cmd, release: func() { once.Do(func() { close(released) }) }}
	c.cleanupResource = func(context.Context) error {
		calls.Add(1)
		select {
		case <-allow:
			return nil
		default:
			return context.DeadlineExceeded
		}
	}
	return c, allow, released, &calls
}

func expectHeld(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("released %s before the tree was verified empty", what)
	default:
	}
}
func expectClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("did not release %s after verified cleanup", what)
	}
}

func TestCleanupFailurePinsRuntimeAndWorkerUntilVerifiedEmpty(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &execution{ExecutionStatus: ExecutionStatus{Handle: strings.Repeat("a", 64), Service: "audit", Key: executionTestKey(991), Version: strings.Repeat("b", 64), State: "running", UID: workerUIDBase}, done: make(chan struct{}), cancel: cancel}
	m.workers[e.UID] = &worker{service: "audit", cancel: cancel, done: e.done}
	m.executions[e.Handle] = e
	var receipts atomic.Int32
	m.attestor = func(ExecutionStatus, IsolationProfile) (string, error) { receipts.Add(1); return "must-not-sign", nil }
	c, allow, released, calls := cleanupFailureFixture(exec.CommandContext(ctx, "sh", "-c", "exit 0"))
	callback := make(chan struct{})
	c.onCleanupFailure = func() { close(callback) }
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.programs, taskDirName, "cleanup-test")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	go m.waitExecution(ctx, e, c, dir)
	expectClosed(t, callback, "cleanup-failure callback")
	expectHeld(t, released, "runtime lease")
	expectHeld(t, e.done, "worker slot")
	m.mu.Lock()
	_, held := m.workers[e.UID]
	m.mu.Unlock()
	if !held {
		t.Fatal("cleanup failure recycled worker identity")
	}
	close(allow)
	expectClosed(t, e.done, "worker slot")
	expectClosed(t, released, "runtime lease")
	m.mu.Lock()
	_, held = m.workers[e.UID]
	state := e.State
	m.mu.Unlock()
	if held || state != "failed" || receipts.Load() != 0 || calls.Load() < 2 || !errors.Is(c.cleanupErr, context.DeadlineExceeded) {
		t.Fatalf("cleanup retry erased failure or retained/recycled authority incorrectly: held=%v state=%s receipts=%d attempts=%d error=%v", held, state, receipts.Load(), calls.Load(), c.cleanupErr)
	}
}

func TestFailedStartQuarantinesWorkerAndCoordinator(t *testing.T) {
	for _, coordinatorCase := range []bool{false, true} {
		t.Run(map[bool]string{false: "worker", true: "coordinator"}[coordinatorCase], func(t *testing.T) {
			root(t)
			m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			cmd, allow, released, _ := cleanupFailureFixture(exec.Command("/missing-sealed-fixture-executable"))
			if err := cmd.Start(); err == nil {
				t.Fatal("fixture did not force exec.Start failure")
			}
			var done <-chan struct{}
			var controller *coordinator
			var ent *entry
			if coordinatorCase {
				ent = &entry{Status: Status{ID: "audit"}, ControllerUID: coordinatorUIDBase}
				controller = &coordinator{cancel: func() {}, done: make(chan struct{})}
				m.entries[ent.ID] = ent
				m.mu.Lock()
				m.holdFailedCoordinator(ent, controller, cmd)
				m.mu.Unlock()
				done = controller.done
			} else {
				e := &execution{ExecutionStatus: ExecutionStatus{Handle: strings.Repeat("c", 64), Service: "audit", State: "failed", UID: workerUIDBase}, done: make(chan struct{})}
				m.workers[e.UID] = &worker{service: "audit", cancel: func() {}, done: e.done}
				m.mu.Lock()
				m.finishFailedExecutionStart(e, cmd)
				m.mu.Unlock()
				done = e.done
			}
			expectHeld(t, released, "failed-start runtime lease")
			expectHeld(t, done, "failed-start identity")
			m.mu.Lock()
			held := len(m.workers) == 1
			if coordinatorCase {
				held = ent.controller == controller
			}
			m.mu.Unlock()
			if !held {
				t.Fatal("failed Start dropped a quarantined identity")
			}
			close(allow)
			expectClosed(t, done, "failed-start identity")
			expectClosed(t, released, "failed-start runtime lease")
			m.mu.Lock()
			held = len(m.workers) != 0
			if coordinatorCase {
				held = ent.controller != nil
			}
			m.mu.Unlock()
			if held {
				t.Fatal("verified empty failed-start slot was not released")
			}
		})
	}
}
