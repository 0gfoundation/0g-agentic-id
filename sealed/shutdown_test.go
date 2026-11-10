package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestStopHooksRunInOrderWithinBudget(t *testing.T) {
	var s stopHooks
	var got []int
	s.add(func(context.Context) { got = append(got, 1) })
	s.add(func(context.Context) { got = append(got, 2) })
	s.run(context.Background())
	if !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("hooks ran %v, want [1 2]", got)
	}

	got = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.run(ctx)
	if got != nil {
		t.Fatalf("hooks ran %v after the budget was spent", got)
	}
}

// exitRecorder captures the exit code handleStopSignals passes.
type exitRecorder struct{ code chan int }

func newExitRecorder() *exitRecorder  { return &exitRecorder{code: make(chan int, 1)} }
func (e *exitRecorder) exit(code int) { e.code <- code }
func (e *exitRecorder) wait(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case c := <-e.code:
		return c
	case <-time.After(within):
		t.Fatal("handleStopSignals did not exit")
		return -1
	}
}

func TestHandleStopSignalsRunsHooksThenExits(t *testing.T) {
	var hooks stopHooks
	ran := make(chan struct{})
	hooks.add(func(context.Context) { close(ran) })
	flushed := false
	sigs := make(chan os.Signal, 2)
	rec := newExitRecorder()
	go handleStopSignals(sigs, &hooks, time.Second, func() { flushed = true }, rec.exit)

	sigs <- syscall.SIGTERM
	if code := rec.wait(t, 2*time.Second); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	select {
	case <-ran:
	default:
		t.Fatal("the stop hook did not run")
	}
	if !flushed {
		t.Fatal("the log was not flushed before exit")
	}
}

func TestHandleStopSignalsSecondSignalExitsAtOnce(t *testing.T) {
	var hooks stopHooks
	release := make(chan struct{})
	defer close(release)
	hooks.add(func(context.Context) { <-release })
	sigs := make(chan os.Signal, 2)
	rec := newExitRecorder()
	go handleStopSignals(sigs, &hooks, time.Minute, func() {}, rec.exit)

	sigs <- syscall.SIGTERM
	sigs <- syscall.SIGTERM
	rec.wait(t, 2*time.Second)
}

func TestHandleStopSignalsExitsWhenBudgetRunsOut(t *testing.T) {
	var hooks stopHooks
	release := make(chan struct{})
	defer close(release)
	hooks.add(func(context.Context) { <-release })
	sigs := make(chan os.Signal, 2)
	rec := newExitRecorder()
	go handleStopSignals(sigs, &hooks, 50*time.Millisecond, func() {}, rec.exit)

	sigs <- syscall.SIGINT
	rec.wait(t, 2*time.Second)
}

// stopFakes records the order in which stopAgentAndCommit drives its parts.
type stopFakes struct {
	mu      sync.Mutex
	order   []string
	done    chan struct{}
	drifted []string
	plain   map[string][]byte
	applied map[string][]byte
	err     error
}

func newStopFakes() *stopFakes {
	return &stopFakes{done: make(chan struct{})}
}

func (f *stopFakes) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.order = append(f.order, s)
}

func (f *stopFakes) Stop() {
	f.record("watcher.Stop")
	close(f.done)
}
func (f *stopFakes) Done() <-chan struct{} { return f.done }
func (f *stopFakes) Final(ctx context.Context, onDrift func(map[string][]byte, []string)) {
	f.record("watcher.Final")
	if len(f.drifted) > 0 {
		onDrift(f.plain, f.drifted)
	}
}

type stopManagerFake struct{ f *stopFakes }

func (m stopManagerFake) Stop(context.Context) { m.f.record("manager.Stop") }

type stopCommitterFake struct{ f *stopFakes }

func (c stopCommitterFake) Apply(_ context.Context, plaintexts map[string][]byte) error {
	c.f.record("uploader.Apply")
	c.f.applied = plaintexts
	return c.f.err
}

func TestStopAgentAndCommitOrder(t *testing.T) {
	f := newStopFakes()
	f.drifted = []string{"skills/"}
	f.plain = map[string][]byte{"skills/": []byte("manifest")}
	stopAgentAndCommit(context.Background(), f, stopManagerFake{f}, stopCommitterFake{f}, func() bool { return false })

	want := []string{"watcher.Stop", "manager.Stop", "watcher.Final", "uploader.Apply"}
	if !reflect.DeepEqual(f.order, want) {
		t.Fatalf("order %v, want %v", f.order, want)
	}
	if string(f.applied["skills/"]) != "manifest" {
		t.Fatalf("committed %v, want the final tick's plaintexts", f.applied)
	}
}

func TestStopAgentAndCommitNothingDrifted(t *testing.T) {
	f := newStopFakes()
	stopAgentAndCommit(context.Background(), f, stopManagerFake{f}, stopCommitterFake{f}, func() bool { return false })
	want := []string{"watcher.Stop", "manager.Stop", "watcher.Final"}
	if !reflect.DeepEqual(f.order, want) {
		t.Fatalf("order %v, want %v", f.order, want)
	}
}

func TestStopAgentAndCommitFailedCommitIsLogged(t *testing.T) {
	f := newStopFakes()
	f.drifted = []string{"APPEND_SYSTEM.md"}
	f.plain = map[string][]byte{"APPEND_SYSTEM.md": []byte("persona")}
	f.err = errors.New("storage unreachable")
	// Returns normally: a failed commit leaves the drift for the next boot
	// to find against chain, and sealed still exits.
	stopAgentAndCommit(context.Background(), f, stopManagerFake{f}, stopCommitterFake{f}, func() bool { return false })
	if f.order[len(f.order)-1] != "uploader.Apply" {
		t.Fatalf("order %v, want the commit attempted last", f.order)
	}
}

func TestStopAgentAndCommitSkipsCommitForNewOwner(t *testing.T) {
	f := newStopFakes()
	f.drifted = []string{"skills/"}
	stopAgentAndCommit(context.Background(), f, stopManagerFake{f}, stopCommitterFake{f}, func() bool { return true })
	want := []string{"watcher.Stop", "manager.Stop"}
	if !reflect.DeepEqual(f.order, want) {
		t.Fatalf("order %v, want %v (no final tick, no commit)", f.order, want)
	}
}

// watcherStuck is a watcher whose tick in progress never finishes.
type watcherStuck struct{ *stopFakes }

func (w watcherStuck) Stop()                 { w.record("watcher.Stop") }
func (w watcherStuck) Done() <-chan struct{} { return nil }

func TestStopAgentAndCommitGivesUpOnAStuckTick(t *testing.T) {
	f := newStopFakes()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	stopAgentAndCommit(ctx, watcherStuck{f}, stopManagerFake{f}, stopCommitterFake{f}, func() bool { return false })
	want := []string{"watcher.Stop"}
	if !reflect.DeepEqual(f.order, want) {
		t.Fatalf("order %v, want %v (nothing after the stuck tick)", f.order, want)
	}
}
