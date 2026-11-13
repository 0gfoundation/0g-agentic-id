package main

import (
	"context"
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

// stopFakes records the order in which stopAgent drives its parts.
type stopFakes struct {
	mu    sync.Mutex
	order []string
	done  chan struct{}
}

func newStopFakes() *stopFakes {
	return &stopFakes{done: make(chan struct{})}
}

func (f *stopFakes) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.order = append(f.order, s)
}

func (f *stopFakes) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...)
}

// An idle watcher: Run returns as soon as Stop is called.
func (f *stopFakes) Stop() {
	f.record("watcher.Stop")
	close(f.done)
}
func (f *stopFakes) Done() <-chan struct{} { return f.done }

type stopManagerFake struct{ f *stopFakes }

func (m stopManagerFake) Stop(context.Context) { m.f.record("manager.Stop") }

func TestStopAgentOrder(t *testing.T) {
	f := newStopFakes()
	stopAgent(context.Background(), f, stopManagerFake{f})
	want := []string{"watcher.Stop", "manager.Stop"}
	if got := f.recorded(); !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

// watcherBusy is a watcher with a tick under way: Run returns when the test
// ends the tick, not when Stop is called.
type watcherBusy struct{ *stopFakes }

func (w watcherBusy) Stop() { w.record("watcher.Stop") }

func TestStopAgentWaitsForTheTickUnderWay(t *testing.T) {
	f := newStopFakes()
	returned := make(chan struct{})
	go func() {
		stopAgent(context.Background(), watcherBusy{f}, stopManagerFake{f})
		close(returned)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(f.recorded()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// The agent is stopped before the tick ends.
	if got, want := f.recorded(), []string{"watcher.Stop", "manager.Stop"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	select {
	case <-returned:
		t.Fatal("stopAgent returned while the tick was under way")
	case <-time.After(20 * time.Millisecond):
	}
	close(f.done)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("stopAgent did not return after the tick ended")
	}
}

func TestStopAgentGivesUpOnAStuckTick(t *testing.T) {
	f := newStopFakes()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	stopAgent(ctx, watcherBusy{f}, stopManagerFake{f})
	want := []string{"watcher.Stop", "manager.Stop"}
	if got := f.recorded(); !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}
