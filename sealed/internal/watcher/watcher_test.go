package watcher

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/platform"
	"seal-verify/internal/state"
)

// fakeAdapter returns a configurable EvolutionFor result per dim. Calls are
// counted so tests can assert tick frequency.
type fakeAdapter struct {
	dims    []string
	current atomic.Pointer[[]byte] // EvolutionFor result; swap to simulate drift
	calls   int32
	evoErr  error
}

func (f *fakeAdapter) Name() string                            { return "fake" }
func (f *fakeAdapter) FrameworkFacts() platform.FrameworkFacts {
	return platform.FrameworkFacts{Home: "~/.fake/", Tracked: []platform.PathNote{{Path: "~/.fake/state", Note: "fake"}}}
}
func (f *fakeAdapter) Version(context.Context) (string, error) { return "0", nil }
func (f *fakeAdapter) Roles() []framework.RoleSpec {
	out := make([]framework.RoleSpec, 0, len(f.dims))
	for _, d := range f.dims {
		out = append(out, framework.RoleSpec{Name: d, Shape: framework.Leaf})
	}
	return out
}
func (f *fakeAdapter) Defaults(string) []byte                        { return nil }
func (f *fakeAdapter) Restore(context.Context, string, []byte) error { return nil }
func (f *fakeAdapter) LoadEntry(context.Context, string, string) ([]byte, error) {
	return nil, framework.ErrUnsupportedDim
}
func (f *fakeAdapter) RestoreEntry(context.Context, string, string, []byte) error {
	return framework.ErrUnsupportedDim
}
func (f *fakeAdapter) Start(context.Context, framework.RuntimeContext) (framework.StartResult, error) {
	return framework.StartResult{}, nil
}
func (f *fakeAdapter) HandleLegacy(context.Context, string, []byte) error { return nil }
func (f *fakeAdapter) Stop(context.Context, time.Duration) error          { return nil }
func (f *fakeAdapter) Liveness(context.Context) error                     { return nil }
func (f *fakeAdapter) Readiness(context.Context) error                    { return nil }
func (f *fakeAdapter) AuthResponse(context.Context) (any, error)          { return map[string]any{}, nil }
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

// stableInitial seeds chainSnapshot with sha256 of "initial" so a tick
// reading "initial" off the fakeAdapter reports no drift.
func TestWatcher_NoDrift_NoChange(t *testing.T) {
	a := &fakeAdapter{dims: []string{"config"}}
	initial := []byte("steady")
	a.current.Store(&initial)

	ag := state.New()
	ag.SeedChainSnapshot("framework", sha256Hex(initial), "0xfw")
	ag.SeedChainSnapshot("config", sha256Hex(initial), "0xroot")

	fired := int32(0)
	w := New(a, ag, Config{
		Interval: 5 * time.Millisecond,
		OnDrift: func(map[string][]byte, []string) {
			atomic.AddInt32(&fired, 1)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	if got := atomic.LoadInt32(&fired); got != 0 {
		t.Errorf("OnDrift fired %d times with no real drift; want 0", got)
	}
}

// Drift detection fires OnDrift with the drifted role + the plaintext map
// captured this tick.
func TestWatcher_DetectsDrift(t *testing.T) {
	a := &fakeAdapter{dims: []string{"config"}}
	v1 := []byte("state-v1")
	a.current.Store(&v1)

	ag := state.New()
	ag.SeedChainSnapshot("config", sha256Hex(v1), "0xroot1")

	var (
		mu       sync.Mutex
		gotPT    map[string][]byte
		gotDrift []string
	)
	w := New(a, ag, Config{
		Interval: 5 * time.Millisecond,
		OnDrift: func(plaintexts map[string][]byte, drifted []string) {
			mu.Lock()
			defer mu.Unlock()
			// Copy on signal so the test can inspect after cancel.
			gotPT = map[string][]byte{}
			for k, v := range plaintexts {
				cp := make([]byte, len(v))
				copy(cp, v)
				gotPT[k] = cp
			}
			gotDrift = append([]string(nil), drifted...)
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// Let one tick run with initial state — should NOT drift (in sync).
	time.Sleep(20 * time.Millisecond)

	// Now swap content. Next tick should see drift.
	v2 := []byte("state-v2-new-content")
	a.current.Store(&v2)

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		if len(gotDrift) > 0 {
			mu.Unlock()
			break
		}
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotDrift) != 1 || gotDrift[0] != "config" {
		t.Errorf("OnDrift drifted = %v; want [config]", gotDrift)
	}
	if pt, ok := gotPT["config"]; !ok || string(pt) != string(v2) {
		t.Errorf("OnDrift plaintexts[config] = %q; want %q", pt, v2)
	}
	// Chain snapshot must not have moved (uploader.Apply would advance it;
	// not invoked here).
	if ch := ag.ChainDataHashes()[0]; ch != sha256Hex(v1) {
		t.Errorf("chain snapshot moved without upload: chain=%s want=%s (v1)", ch, sha256Hex(v1))
	}
}

// Reconciliation property: if OnDrift is called repeatedly across ticks
// (e.g. handler fails to upload), the watcher keeps firing as long as
// chainSnapshot stays stale. This is the "failed upload remembers, next
// tick retries" property the design pivots on.
func TestWatcher_DriftPersistsAcrossTicks(t *testing.T) {
	a := &fakeAdapter{dims: []string{"config"}}
	v1 := []byte("v1")
	a.current.Store(&v1)

	ag := state.New()
	ag.SeedChainSnapshot("config", sha256Hex(v1), "0xroot1")

	v2 := []byte("v2-drift")
	a.current.Store(&v2)

	var fires int32
	w := New(a, ag, Config{
		Interval: 3 * time.Millisecond,
		OnDrift:  func(map[string][]byte, []string) { atomic.AddInt32(&fires, 1) },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	if got := atomic.LoadInt32(&fires); got < 3 {
		t.Errorf("OnDrift fired %d times; expected ≥3 (drift unresolved across multiple ticks)", got)
	}
}

func TestWatcher_StopHaltsLoop(t *testing.T) {
	a := &fakeAdapter{dims: []string{"config"}}
	v1 := []byte("x")
	a.current.Store(&v1)

	ag := state.New()
	ag.SeedChainSnapshot("config", sha256Hex(v1), "0xroot")

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
