package servicehost

import (
	"context"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

// A completion signal must include the supervisor's state cleanup, not just
// process exit. Hold the state lock to expose the old ordering deterministically:
// closing done here would let Stop return with a dead controller still attached.
func TestCoordinatorCompletionWaitsForStateCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &coordinator{cancel: cancel, done: make(chan struct{}), cmd: cmd, server: &http.Server{}}
	e := &entry{Status: Status{ID: "completion", State: "stopped"}, controller: c, generation: 2}
	m := &Manager{stopGC: make(chan struct{})}
	m.mu.Lock()
	go m.superviseCoordinator(ctx, e, c, 1)
	var premature bool
	select {
	case <-ctx.Done(): // Wait returned and the supervisor has started cleanup.
	case <-time.After(3 * time.Second):
		m.mu.Unlock()
		t.Fatal("coordinator did not exit")
	}
	select {
	case <-c.done:
		premature = true
	case <-time.After(150 * time.Millisecond):
	}
	m.mu.Unlock()
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor cleanup did not complete")
	}
	m.mu.Lock()
	attached := e.controller != nil
	m.mu.Unlock()
	if premature {
		t.Fatal("coordinator completion signalled before manager state cleanup")
	}
	if attached {
		t.Fatal("completed coordinator remained attached")
	}
}

func TestCoordinatorStopThenStartRestartsService(t *testing.T) {
	m := executionManager(t)
	waitRunning := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			m.mu.Lock()
			e := m.entries["first"]
			running := e.Desired && e.State == "running" && e.controller != nil
			m.mu.Unlock()
			if running {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("coordinator did not become running")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitRunning()
	for range 8 {
		if _, err := m.Stop("first"); err != nil {
			t.Fatal(err)
		}
		m.mu.Lock()
		attached := m.entries["first"].controller != nil
		m.mu.Unlock()
		if attached {
			t.Fatal("Stop returned before clearing the old coordinator")
		}
		if _, err := m.Start("first"); err != nil {
			t.Fatal(err)
		}
		waitRunning()
	}
}
