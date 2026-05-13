// Package watcher periodically polls the framework adapter for each
// dimension's current state, hashes the result, and updates
// state.currentSnapshot when drift is detected.
//
// This is the "agent -> state" half of the evolution pipeline:
//
//	watcher (this) -> state.UpdateCurrent -> (proxy /hello picks up new hash)
//	                                        ↓
//	                                    evaluator decides upload
//	                                        ↓
//	                                    uploader -> state.RecordChainUpload
//
// Watcher does NOT decide whether to upload -- that's the evaluator's job.
// Watcher's only mutation is state.UpdateCurrent. Logging in state's
// UpdateCurrent makes drift visible without watcher needing to log.
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

	// OnDimDrift, if non-nil, is invoked once per drifted dim per tick
	// (not when a dim stays stable). Hands off to the bootstrap layer
	// for dim-specific reactions: framework drift triggers
	// reconcile + manager.Reload; other dims may schedule an iData
	// chain push via the uploader. Errors thrown by the callback are
	// the caller's responsibility — watcher just dispatches.
	OnDimDrift func(dim string)
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

// dimsToPoll returns the protocol-reserved "framework" plus every adapter-
// owned dim. framework drift detection is critical (catches dashboard
// upgrades / npm version drift) and the adapter's Dimensions() doesn't
// include it (per EVOLUTION_DESIGN §7.1), so we prepend it here.
func (w *Watcher) dimsToPoll() []string {
	return append([]string{"framework"}, w.adapter.Dimensions()...)
}

// tick runs a single poll cycle: for each dim, ask adapter for current
// canonical bytes, sha256, push to state if drifted. Errors are logged
// per-dim and don't abort the cycle.
//
// At the end of each tick we emit a single-line summary so /log readers
// can see "watcher is alive and these are the current per-dim hashes"
// even when there's no drift. Drift events get their own detailed log
// from state.UpdateCurrent.
func (w *Watcher) tick(ctx context.Context) {
	type dimHash struct {
		dim     string
		hash    string
		size    int
		drifted bool
	}
	results := make([]dimHash, 0, 5)

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
		drifted := w.agent.UpdateCurrent(dim, hash)
		results = append(results, dimHash{dim, hash, len(bytes), drifted})
	}

	// Single summary line per tick. Drift dims marked with !; stable dims
	// just show their truncated hash + plaintext size.
	var parts []string
	driftCount := 0
	for _, r := range results {
		marker := ""
		if r.drifted {
			marker = "!"
			driftCount++
		}
		parts = append(parts, fmt.Sprintf("%s%s=%s/%dB", marker, r.dim, r.hash[:8], r.size))
	}
	if driftCount > 0 {
		logger.Logf("watcher: tick -- %d drifted: %s", driftCount, strings.Join(parts, " "))
	} else {
		logger.Logf("watcher: tick -- stable: %s", strings.Join(parts, " "))
	}

	// Dispatch drift callbacks AFTER logging so the summary line prints
	// even if a callback panics (recover would still let other handlers
	// run, but visibility into "what drifted" is preserved either way).
	if w.cfg.OnDimDrift != nil {
		for _, r := range results {
			if r.drifted {
				w.cfg.OnDimDrift(r.dim)
			}
		}
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
