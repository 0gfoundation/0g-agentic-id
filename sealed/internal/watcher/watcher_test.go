package watcher

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/state"
)

// fakeAdapter returns a configurable EvolutionFor result per dim. Calls are
// counted so tests can assert tick frequency.
type fakeAdapter struct {
	dims         []string
	current      atomic.Pointer[[]byte] // EvolutionFor result; swap to simulate drift
	calls        int32
	evoErr       error
}

func (f *fakeAdapter) Name() string                                                { return "fake" }
func (f *fakeAdapter) Version(context.Context) (string, error)                     { return "0", nil }
func (f *fakeAdapter) Dimensions() []string                                         { return f.dims }
func (f *fakeAdapter) Restore(context.Context, string, []byte) error                { return nil }
func (f *fakeAdapter) Start(context.Context, framework.RuntimeContext) (framework.StartResult, error) {
	return framework.StartResult{}, nil
}
func (f *fakeAdapter) Stop(context.Context, time.Duration) error { return nil }
func (f *fakeAdapter) Liveness(context.Context) error             { return nil }
func (f *fakeAdapter) Readiness(context.Context) error            { return nil }
func (f *fakeAdapter) AuthResponse(context.Context) (any, error)  { return map[string]any{}, nil }
func (f *fakeAdapter) EvolutionFor(ctx context.Context, dim string) ([]byte, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.evoErr != nil {
		return nil, f.evoErr
	}
	if p := f.current.Load(); p != nil {
		return *p, nil
	}
	return []byte("initial"), nil
}

func TestWatcher_NoDrift_NoChange(t *testing.T) {
	a := &fakeAdapter{dims: []string{"config"}}
	initial := []byte("steady")
	a.current.Store(&initial)

	ag := state.New()
	// Watcher polls framework + adapter.Dimensions(); seed both with the
	// same content hash so polling produces no phantom drift.
	ag.SeedSnapshots("framework", sha256Hex(initial), "0xfw")
	ag.SeedSnapshots("config", sha256Hex(initial), "0xroot")

	w := New(a, ag, Config{Interval: 5 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	if !equalSorted(ag.CurrentDataHashes(), ag.ChainDataHashes()) {
		t.Errorf("snapshots drifted with no real drift: current=%v chain=%v",
			ag.CurrentDataHashes(), ag.ChainDataHashes())
	}
}

func TestWatcher_DetectsDrift(t *testing.T) {
	a := &fakeAdapter{dims: []string{"config"}}
	v1 := []byte("state-v1")
	a.current.Store(&v1)

	ag := state.New()
	ag.SeedSnapshots("framework", sha256Hex(v1), "0xfw")
	ag.SeedSnapshots("config", sha256Hex(v1), "0xroot1")

	w := New(a, ag, Config{Interval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// Give one tick to confirm steady state.
	time.Sleep(20 * time.Millisecond)
	if cur := ag.CurrentDataHashes(); cur[0] != sha256Hex(v1) {
		t.Fatalf("pre-drift current = %v; want sha256(v1)", cur)
	}

	// Simulate agent self-modification.
	v2 := []byte("state-v2-new-content")
	a.current.Store(&v2)

	// Wait for watcher to pick up.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ag.CurrentDataHashes()[0] == sha256Hex(v2) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if cur := ag.CurrentDataHashes()[0]; cur != sha256Hex(v2) {
		t.Errorf("watcher missed drift: current=%s want=%s", cur, sha256Hex(v2))
	}
	// Chain snapshot must not have moved.
	if ch := ag.ChainDataHashes()[0]; ch != sha256Hex(v1) {
		t.Errorf("chain snapshot moved without upload: chain=%s want=%s (v1)", ch, sha256Hex(v1))
	}
	if !ag.HasChanges() {
		t.Errorf("HasChanges() = false after drift; want true")
	}
}

func TestWatcher_StopHaltsLoop(t *testing.T) {
	a := &fakeAdapter{dims: []string{"config"}}
	v1 := []byte("x")
	a.current.Store(&v1)

	ag := state.New()
	ag.SeedSnapshots("framework", sha256Hex(v1), "0xfw")
	ag.SeedSnapshots("config", sha256Hex(v1), "0xroot")

	w := New(a, ag, Config{Interval: 3 * time.Millisecond})
	go w.Run(context.Background())

	time.Sleep(20 * time.Millisecond)
	prev := atomic.LoadInt32(&a.calls)
	w.Stop()
	time.Sleep(20 * time.Millisecond)
	post := atomic.LoadInt32(&a.calls)
	if post-prev > 1 {
		t.Errorf("watcher kept polling after Stop: prev=%d post=%d", prev, post)
	}
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
