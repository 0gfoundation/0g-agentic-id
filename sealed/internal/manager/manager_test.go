package manager

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/state"
)

// fakeAdapter is a controllable Adapter for unit tests. Each method can be
// overridden via callbacks; absence of an override returns the corresponding
// default zero value / nil.
type fakeAdapter struct {
	mu sync.Mutex

	startCalls    int32
	stopCalls     int32
	livenessCalls int32

	startFn    func(rt framework.RuntimeContext) (framework.StartResult, error)
	stopFn     func() error
	livenessFn func() error

	exitCB func(err error)
}

func (f *fakeAdapter) Name() string                                                 { return "fake" }
func (f *fakeAdapter) Version(ctx context.Context) (string, error)                  { return "1.0", nil }
func (f *fakeAdapter) Dimensions() []string                                          { return []string{"config"} }
func (f *fakeAdapter) Restore(ctx context.Context, dim string, p []byte) error       { return nil }
func (f *fakeAdapter) EvolutionFor(ctx context.Context, dim string) ([]byte, error)  { return nil, nil }
func (f *fakeAdapter) Readiness(ctx context.Context) error                           { return nil }
func (f *fakeAdapter) AuthResponse(ctx context.Context) (any, error)                 { return map[string]any{}, nil }

func (f *fakeAdapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	atomic.AddInt32(&f.startCalls, 1)
	if f.startFn != nil {
		return f.startFn(rt)
	}
	return framework.StartResult{Upstream: "http://127.0.0.1:0", PID: 0}, nil
}

func (f *fakeAdapter) Stop(ctx context.Context, gracefulTimeout time.Duration) error {
	atomic.AddInt32(&f.stopCalls, 1)
	if f.stopFn != nil {
		return f.stopFn()
	}
	return nil
}

func (f *fakeAdapter) Liveness(ctx context.Context) error {
	atomic.AddInt32(&f.livenessCalls, 1)
	if f.livenessFn != nil {
		return f.livenessFn()
	}
	return nil
}

func (f *fakeAdapter) MonitorExit(onExit func(err error)) {
	f.mu.Lock()
	f.exitCB = onExit
	f.mu.Unlock()
}

// triggerExit manually fires the registered exit callback (simulating a
// process death).
func (f *fakeAdapter) triggerExit(err error) {
	f.mu.Lock()
	cb := f.exitCB
	f.mu.Unlock()
	if cb != nil {
		cb(err)
	}
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestBackoffFor(t *testing.T) {
	m := New(&fakeAdapter{}, state.New(), Config{})
	cases := []struct {
		i    int
		want time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{6, 60 * time.Second},
		{7, 60 * time.Second}, // beyond seq -> last
		{99, 60 * time.Second},
		{-1, 0},
	}
	for _, c := range cases {
		got := m.backoffFor(c.i)
		if got != c.want {
			t.Errorf("backoffFor(%d): got %s want %s", c.i, got, c.want)
		}
	}
}

func TestStart_AppliesDefaults(t *testing.T) {
	m := New(&fakeAdapter{}, state.New(), Config{})
	if m.cfg.LivenessProbeInterval != 5*time.Second {
		t.Errorf("default LivenessProbeInterval = %s; want 5s", m.cfg.LivenessProbeInterval)
	}
	if m.cfg.MaxRetries != 5 {
		t.Errorf("default MaxRetries = %d; want 5", m.cfg.MaxRetries)
	}
	if len(m.cfg.BackoffSeq) != 7 {
		t.Errorf("default BackoffSeq len = %d; want 7", len(m.cfg.BackoffSeq))
	}
}

func TestStart_FirstAttemptError_NoRetry(t *testing.T) {
	// First start failure should bubble up, not trigger restart loop.
	bootErr := errors.New("binary missing")
	a := &fakeAdapter{
		startFn: func(rt framework.RuntimeContext) (framework.StartResult, error) {
			return framework.StartResult{}, bootErr
		},
	}
	m := New(a, state.New(), Config{
		LivenessProbeInterval: 10 * time.Millisecond,
		BackoffSeq:            []time.Duration{1 * time.Millisecond},
		MaxRetries:            3,
	})
	err := m.Start(context.Background(), StartParams{})
	if !errors.Is(err, bootErr) {
		t.Errorf("got err %v; want %v", err, bootErr)
	}
	if atomic.LoadInt32(&a.startCalls) != 1 {
		t.Errorf("expected exactly 1 start call on initial failure, got %d", a.startCalls)
	}
}

func TestRestart_OnExit_WithinThreshold(t *testing.T) {
	// Start succeeds; trigger exit; expect 1 restart attempt then steady state.
	startCh := make(chan struct{}, 5)
	a := &fakeAdapter{
		startFn: func(rt framework.RuntimeContext) (framework.StartResult, error) {
			startCh <- struct{}{}
			return framework.StartResult{Upstream: "http://x"}, nil
		},
	}
	ag := state.New()
	m := New(a, ag, Config{
		LivenessProbeInterval: 1 * time.Hour, // disable probe noise for this test
		BackoffSeq:            []time.Duration{1 * time.Millisecond},
		MaxRetries:            3,
		GracefulStopTimeout:   1 * time.Millisecond,
	})
	if err := m.Start(context.Background(), StartParams{}); err != nil {
		t.Fatal(err)
	}
	<-startCh // initial Start

	// Trigger one process death.
	a.triggerExit(errors.New("crashed"))

	// Wait for the restart Start.
	select {
	case <-startCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected restart Start, got start_calls=%d", atomic.LoadInt32(&a.startCalls))
	}

	// State should be Running again.
	time.Sleep(20 * time.Millisecond)
	if p := ag.Phase(); p != state.PhaseRunning {
		t.Errorf("phase after successful restart = %v; want PhaseRunning", p)
	}
}

func TestRestart_ExhaustsRetries_EntersFailed(t *testing.T) {
	bootErr := errors.New("permanent failure")
	startCount := int32(0)
	a := &fakeAdapter{
		startFn: func(rt framework.RuntimeContext) (framework.StartResult, error) {
			n := atomic.AddInt32(&startCount, 1)
			if n == 1 {
				// First start succeeds (the initial Start).
				return framework.StartResult{Upstream: "http://x"}, nil
			}
			// All restart attempts fail.
			return framework.StartResult{}, bootErr
		},
	}
	failedCh := make(chan error, 1)
	ag := state.New()
	m := New(a, ag, Config{
		LivenessProbeInterval: 1 * time.Hour,
		BackoffSeq:            []time.Duration{1 * time.Millisecond},
		MaxRetries:            3,
		GracefulStopTimeout:   1 * time.Millisecond,
		OnFailed: func(err error) {
			failedCh <- err
		},
	})
	if err := m.Start(context.Background(), StartParams{}); err != nil {
		t.Fatal(err)
	}
	a.triggerExit(errors.New("died"))

	select {
	case err := <-failedCh:
		if !errors.Is(err, bootErr) {
			t.Errorf("OnFailed err = %v; want wrap of %v", err, bootErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected OnFailed within timeout; start_calls=%d phase=%v",
			atomic.LoadInt32(&startCount), ag.Phase())
	}
	if p := ag.Phase(); p != state.PhaseFailed {
		t.Errorf("phase after exhausted retries = %v; want PhaseFailed", p)
	}
	// 1 initial start + 3 restart attempts = 4
	if got := atomic.LoadInt32(&startCount); got != 4 {
		t.Errorf("expected 4 start calls (1 initial + 3 retries); got %d", got)
	}
}

func TestRestart_DoubleTriggerCoalesces(t *testing.T) {
	// Both liveness probe and MonitorExit firing concurrently must NOT cause
	// two parallel restart sequences.
	startCh := make(chan struct{}, 10)
	a := &fakeAdapter{
		startFn: func(rt framework.RuntimeContext) (framework.StartResult, error) {
			startCh <- struct{}{}
			return framework.StartResult{Upstream: "http://x"}, nil
		},
	}
	ag := state.New()
	m := New(a, ag, Config{
		LivenessProbeInterval: 1 * time.Hour,
		BackoffSeq:            []time.Duration{20 * time.Millisecond}, // long enough for race window
		MaxRetries:            3,
		GracefulStopTimeout:   1 * time.Millisecond,
	})
	if err := m.Start(context.Background(), StartParams{}); err != nil {
		t.Fatal(err)
	}
	<-startCh

	// Fire two restarts back-to-back; only one should win.
	go m.tryRestart(context.Background())
	go m.tryRestart(context.Background())

	// Allow time for both to attempt and the winner's restart to complete.
	time.Sleep(80 * time.Millisecond)

	// Drain start channel.
	count := 0
loop:
	for {
		select {
		case <-startCh:
			count++
		default:
			break loop
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 restart Start, got %d (double-trigger guard failed)", count)
	}
}

func TestStop_HaltsLivenessLoop(t *testing.T) {
	probeCount := int32(0)
	a := &fakeAdapter{
		livenessFn: func() error {
			atomic.AddInt32(&probeCount, 1)
			return nil
		},
	}
	m := New(a, state.New(), Config{
		LivenessProbeInterval: 5 * time.Millisecond,
		BackoffSeq:            []time.Duration{1 * time.Millisecond},
		MaxRetries:            3,
	})
	if err := m.Start(context.Background(), StartParams{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	prev := atomic.LoadInt32(&probeCount)
	m.Stop(context.Background())
	time.Sleep(30 * time.Millisecond)
	post := atomic.LoadInt32(&probeCount)
	if post-prev > 1 {
		t.Errorf("liveness loop kept probing after Stop: prev=%d post=%d", prev, post)
	}
}
