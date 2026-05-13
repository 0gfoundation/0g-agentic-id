// Package manager owns the agent process lifecycle: spawn, liveness probe,
// restart-on-death with backoff, and a max-retries threshold that escalates
// to PhaseFailed.
//
// The manager intentionally does NOT contain framework knowledge — all
// process-control primitives live behind the Adapter interface, so the same
// manager works for openclaw, eliza, or any future adapter.
//
// Lifecycle invariants:
//
//   - Exactly one restart attempt sequence is in flight at any moment
//     (atomic guard via inFlight bool).
//   - On successful (re-)start, manager re-arms state.Agent with the same
//     identity material that was passed to the initial Start (sealID, owner,
//     dataHashes, agentConfig). Only Upstream + Secret change.
//   - On exhausted retries, state.Phase transitions to Failed and the
//     OnFailed callback (if set) fires once. The HTTP server keeps running
//     so /healthz and /log remain reachable for diagnostics.
package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/state"
)

// Adapter is the minimal subset of framework.Framework the manager needs,
// extended with MonitorExit so the manager can observe agent process death
// without polling.
type Adapter interface {
	framework.Framework
	MonitorExit(onExit func(err error))
}

// Config tunes supervisor behaviour. Zero-value Config is replaced with
// sensible defaults at construction time (see New).
type Config struct {
	// LivenessProbeInterval is how often manager calls Adapter.Liveness.
	// Default: 5s.
	LivenessProbeInterval time.Duration

	// BackoffSeq is the per-attempt delay before each restart attempt.
	// Index 0 is the delay before attempt #1. Last entry is reused once the
	// sequence is exhausted (so a long-running restart loop keeps the final
	// delay rather than dropping back to zero).
	// Default: 1s, 2s, 4s, 8s, 16s, 30s, 60s.
	BackoffSeq []time.Duration

	// MaxRetries caps how many restart attempts run before giving up and
	// transitioning to PhaseFailed. Default: 5. Negative value = retry forever.
	MaxRetries int

	// GracefulStopTimeout is passed to Adapter.Stop during restart. Default: 10s.
	GracefulStopTimeout time.Duration

	// OnFailed is invoked once when the manager exhausts retries and
	// transitions to PhaseFailed. Pass an attestor reporter call here.
	OnFailed func(err error)
}

func (c *Config) applyDefaults() {
	if c.LivenessProbeInterval == 0 {
		c.LivenessProbeInterval = 5 * time.Second
	}
	if len(c.BackoffSeq) == 0 {
		c.BackoffSeq = []time.Duration{
			1 * time.Second,
			2 * time.Second,
			4 * time.Second,
			8 * time.Second,
			16 * time.Second,
			30 * time.Second,
			60 * time.Second,
		}
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 5
	}
	if c.GracefulStopTimeout == 0 {
		c.GracefulStopTimeout = 10 * time.Second
	}
}

// StartParams bundles everything manager needs to (re-)arm state on a fresh
// Start call. The agent identity material (priv, sealID, owner) is captured
// once at the initial Start and replayed on every successful restart. iData
// snapshots live in state.Agent and are managed by the bootstrap (seed) +
// watcher (current) + uploader (chain) — manager does not touch them.
//
// Framework-specific configuration is NOT in this struct: the manager talks
// to the adapter through the abstract framework.Framework interface and
// never inspects the framework's config shape.
type StartParams struct {
	Runtime       framework.RuntimeContext
	AgentSealPriv []byte
	SealID        string
	Owner         string
}

// Manager wires an Adapter to the shared agent state, supervised.
type Manager struct {
	adapter Adapter
	agent   *state.Agent
	cfg     Config

	// Saved at the first Start; replayed on each restart.
	params StartParams

	// inFlight ensures only one restart sequence runs at a time. It also
	// guards against a stale liveness goroutine triggering a restart when
	// MonitorExit already started one.
	inFlight atomic.Bool

	// stopCh is closed by Stop() to signal liveness loop to exit. Liveness
	// loops created during a restart are tied to the same channel, so
	// Stop tears down everything.
	stopCh chan struct{}
	once   sync.Once
}

// New constructs a Manager. Adapter must already have its Restore calls
// completed (config in place). cfg is normalized to defaults internally.
func New(adapter Adapter, agent *state.Agent, cfg Config) *Manager {
	cfg.applyDefaults()
	return &Manager{
		adapter: adapter,
		agent:   agent,
		cfg:     cfg,
		stopCh:  make(chan struct{}),
	}
}

// Start launches the agent process, arms shared state, and begins
// supervision. It returns when the initial Adapter.Start succeeds; the
// manager then runs liveness probing + restart-on-failure in goroutines.
//
// If Adapter.Start returns an error on the very first attempt, no restart
// is attempted — that's a hard config issue (binary missing, port in use,
// etc.) and the caller should treat it as a fatal startup failure.
func (m *Manager) Start(ctx context.Context, params StartParams) error {
	m.params = params

	res, err := m.adapter.Start(ctx, params.Runtime)
	if err != nil {
		return err
	}
	m.armState(res)
	m.hookLifecycle(ctx)
	logger.Logf("manager: agent armed, supervision active (probe=%s, max_retries=%d)",
		m.cfg.LivenessProbeInterval, m.cfg.MaxRetries)
	return nil
}

// Stop terminates supervision and the agent process. Idempotent.
func (m *Manager) Stop(ctx context.Context) {
	m.once.Do(func() { close(m.stopCh) })
	_ = m.adapter.Stop(ctx, m.cfg.GracefulStopTimeout)
	m.agent.Clear()
}

// Reload stops the running agent and re-spawns it. Used by the watcher
// when a framework dim drift requires the binary on disk to actually
// take effect (Node modules already loaded in memory don't get swapped
// in-place by an npm install). Args / runtime context are replayed from
// the StartParams captured at the initial Start.
//
// Concurrent Reload + auto-restart attempts coalesce on inFlight (same
// guard as restart()).
func (m *Manager) Reload(ctx context.Context) error {
	if !m.inFlight.CompareAndSwap(false, true) {
		logger.Logf("manager: reload requested while another (re-)start is in flight; skipping")
		return nil
	}
	defer m.inFlight.Store(false)

	logger.Logf("manager: reload — stopping current process")
	if err := m.adapter.Stop(ctx, m.cfg.GracefulStopTimeout); err != nil {
		return fmt.Errorf("reload stop: %w", err)
	}
	logger.Logf("manager: reload — spawning replacement")
	res, err := m.adapter.Start(ctx, m.params.Runtime)
	if err != nil {
		m.agent.SetPhase(state.PhaseFailed)
		return fmt.Errorf("reload start: %w", err)
	}
	m.armState(res)
	m.hookLifecycle(ctx)
	logger.Logf("manager: reload complete; back to Running")
	return nil
}

// ── Internal lifecycle ──────────────────────────────────────────────────────

func (m *Manager) armState(res framework.StartResult) {
	// Identity / runtime fields. Snapshot data is seeded separately by
	// bootstrap (via SeedSnapshots) and updated at runtime by the watcher
	// (UpdateCurrent) — manager doesn't touch snapshots on (re-)start.
	m.agent.Set(
		m.params.AgentSealPriv,
		res.Upstream,
		m.params.SealID,
		m.params.Owner,
	)
}

// hookLifecycle wires up the death watcher + liveness probe for a freshly
// (re-)started process. Each successful Start replaces the previous hooks.
//
// Liveness probe is the source of truth for "agent is unreachable". Process
// exit (cmd.Wait returning) is treated as a hint, not a verdict:
//
//   - non-zero exit  → real crash; restart immediately (don't wait for probe)
//   - exit 0         → may be a framework-internal restart that fork-exec'd a
//                      child to take over the socket (e.g. openclaw 5.x's
//                      handleRestartAfterServerClose path). Defer to the
//                      liveness probe; if the child actually took over,
//                      probe stays green and we don't compete.
//
// Without this distinction we race openclaw's self-restart and crashloop the
// agent (each spawn briefly listens, then exits 0 to hand off to a child we
// don't track, but our restart preempts it).
func (m *Manager) hookLifecycle(ctx context.Context) {
	m.adapter.MonitorExit(func(err error) {
		if err != nil {
			logger.Logf("manager: process exited with error: %v", err)
			go m.tryRestart(ctx)
			return
		}
		logger.Logf("manager: process exited cleanly; deferring to liveness probe")
	})

	go m.runLivenessLoop(ctx)
}

func (m *Manager) runLivenessLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.LivenessProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
		}
		// Skip probing while a restart is in flight — adapter.Liveness will
		// fail anyway during the gap, no need for noise.
		if m.inFlight.Load() {
			continue
		}
		if err := m.adapter.Liveness(ctx); err != nil {
			logger.Logf("manager: liveness probe failed: %v", err)
			go m.tryRestart(ctx)
			return // a fresh liveness loop is started by hookLifecycle on success
		}
	}
}

// tryRestart guarantees only one restart sequence runs at a time. If a
// concurrent caller (e.g. liveness probe + MonitorExit firing on the same
// process death) tries to start one, only the first wins.
func (m *Manager) tryRestart(ctx context.Context) {
	if !m.inFlight.CompareAndSwap(false, true) {
		return
	}
	defer m.inFlight.Store(false)
	m.restart(ctx)
}

func (m *Manager) restart(ctx context.Context) {
	m.agent.SetPhase(state.PhaseRestarting)
	logger.Logf("manager: entering Restarting phase")

	var lastErr error
	for attempt := 1; m.cfg.MaxRetries < 0 || attempt <= m.cfg.MaxRetries; attempt++ {
		backoff := m.backoffFor(attempt - 1)
		logger.Logf("manager: restart attempt %d/%d after %s", attempt, m.cfg.MaxRetries, backoff)

		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-time.After(backoff):
		}

		// Best-effort stop in case the adapter still holds a stale process.
		_ = m.adapter.Stop(ctx, m.cfg.GracefulStopTimeout)

		res, err := m.adapter.Start(ctx, m.params.Runtime)
		if err != nil {
			logger.Logf("manager: restart attempt %d failed: %v", attempt, err)
			lastErr = err
			continue
		}

		m.armState(res)
		m.hookLifecycle(ctx)
		logger.Logf("manager: restart attempt %d succeeded; back to Running", attempt)
		return
	}

	if lastErr == nil {
		lastErr = errors.New("max retries exceeded with no specific adapter error")
	}
	logger.Logf("manager: max retries (%d) exceeded; entering Failed: %v", m.cfg.MaxRetries, lastErr)
	m.agent.SetPhase(state.PhaseFailed)
	if m.cfg.OnFailed != nil {
		m.cfg.OnFailed(lastErr)
	}
}

// backoffFor returns the delay for the (i+1)-th attempt. Beyond the sequence
// length the last value is reused — so an infinite-retry config doesn't drop
// back to zero.
func (m *Manager) backoffFor(i int) time.Duration {
	if i >= len(m.cfg.BackoffSeq) {
		i = len(m.cfg.BackoffSeq) - 1
	}
	if i < 0 {
		return 0
	}
	return m.cfg.BackoffSeq[i]
}
