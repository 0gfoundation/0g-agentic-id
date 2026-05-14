// Package watcher periodically polls the framework adapter for each
// dimension's current state, hashes the result, and updates
// state.currentSnapshot when drift is detected.
//
// This is the "agent -> state" half of the evolution pipeline:
//
//	watcher (this) -> state.UpdateCurrentSnapshot -> (proxy /hello picks up new hash)
//	                                        ↓
//	                                    evaluator decides upload
//	                                        ↓
//	                                    uploader -> state.RecordChainUpload
//
// Watcher does NOT decide whether to upload -- that's the evaluator's job.
// Watcher's only mutation is state.UpdateCurrentSnapshot. Logging in state's
// UpdateCurrentSnapshot makes drift visible without watcher needing to log.
package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/state"
)

// Default polling interval. 30s is a balance between detection latency
// (typical evolution event = dashboard click -> ~5-30s for filesystem
// changes to settle) and adapter call overhead (npm version probe + reads).
const DefaultInterval = 30 * time.Second

// Config tunes watcher behaviour. Zero-value is replaced with defaults.
type Config struct {
	// Interval between poll cycles. Default: 30s.
	Interval time.Duration

	// OnDrift, if non-nil, is invoked exactly once per tick whenever
	// at least one role's disk hash differs from chainSnapshot
	// (current != chain). Receives the full plaintext map captured
	// this tick so the handler can route framework drift specially
	// AND call uploader.Apply with the same plaintexts without re-
	// reading disk. drifted is the subset of roles that triggered
	// the fire; handler decides what to do with each.
	//
	// No fire on stable ticks (all roles in sync). Errors thrown by
	// the callback are the caller's responsibility — watcher just
	// dispatches.
	OnDrift func(plaintexts map[string][]byte, drifted []string)
}

func (c *Config) applyDefaults() {
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
}

// Watcher polls the framework adapter on a tick and feeds drift into state.
type Watcher struct {
	adapter framework.Framework
	agent   *state.Agent
	cfg     Config

	stopCh chan struct{}
	once   sync.Once
}

// New constructs a Watcher. cfg is normalized to defaults internally.
func New(adapter framework.Framework, agent *state.Agent, cfg Config) *Watcher {
	cfg.applyDefaults()
	return &Watcher{
		adapter: adapter,
		agent:   agent,
		cfg:     cfg,
		stopCh:  make(chan struct{}),
	}
}

// Run blocks until ctx is cancelled or Stop is called. Spawn it in a
// goroutine; main.go does this once after the agent is up.
func (w *Watcher) Run(ctx context.Context) {
	logger.Logf("watcher: started (interval=%s, dims=%v)", w.cfg.Interval, w.dimsToPoll())
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Logf("watcher: context cancelled, stopping")
			return
		case <-w.stopCh:
			logger.Logf("watcher: stop requested, stopping")
			return
		case <-ticker.C:
		}
		w.tick(ctx)
	}
}

// Stop signals Run to exit. Idempotent.
func (w *Watcher) Stop() {
	w.once.Do(func() { close(w.stopCh) })
}

// dimsToPoll returns the role names this watcher should poll on every
// tick — exactly the role set the adapter declares (path-driven; see
// EVOLUTION_DESIGN §16.2). "framework" is included by adapter.Roles(),
// not prepended separately, since it's just one role among others now.
func (w *Watcher) dimsToPoll() []string {
	roles := w.adapter.Roles()
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Name)
	}
	return out
}

// tick runs a single poll cycle: for each declared role, read disk via
// EvolutionFor, hash it, advance currentSnapshot, and remember the
// plaintext. After visiting every role, fire OnDrift exactly once with
// the (plaintexts, drifted) pair if anything actually diverged from
// chainSnapshot.
//
// One summary log line per tick — drift roles marked with `!`.
func (w *Watcher) tick(ctx context.Context) {
	type dimResult struct {
		dim     string
		hash    string
		size    int
		drifted bool
	}
	results := make([]dimResult, 0, 5)
	plaintexts := make(map[string][]byte, 5)

	for _, dim := range w.dimsToPoll() {
		bytes, err := w.adapter.EvolutionFor(ctx, dim)
		if err != nil {
			if errors.Is(err, framework.ErrUnsupportedDim) {
				continue
			}
			logger.Logf("watcher: EvolutionFor[%s] error: %v", dim, err)
			continue
		}
		hash := sha256Hex(bytes)
		drifted := w.agent.UpdateCurrentSnapshot(dim, hash)
		results = append(results, dimResult{dim, hash, len(bytes), drifted})
		plaintexts[dim] = bytes
	}

	var parts []string
	var driftedRoles []string
	for _, r := range results {
		marker := ""
		if r.drifted {
			marker = "!"
			driftedRoles = append(driftedRoles, r.dim)
		}
		parts = append(parts, fmt.Sprintf("%s%s=%s/%dB", marker, r.dim, r.hash[:8], r.size))
	}
	if len(driftedRoles) > 0 {
		logger.Logf("watcher: tick -- %d drifted: %s", len(driftedRoles), strings.Join(parts, " "))
	} else {
		logger.Logf("watcher: tick -- stable: %s", strings.Join(parts, " "))
	}

	// Single dispatch after logging so the summary always lands even if
	// the callback panics.
	if w.cfg.OnDrift != nil && len(driftedRoles) > 0 {
		w.cfg.OnDrift(plaintexts, driftedRoles)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
