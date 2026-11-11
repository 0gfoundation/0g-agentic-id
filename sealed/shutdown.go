package main

// Graceful stop, for sealed running under the loader (cmd/loader).
//
// On SIGTERM or SIGINT sealed stops the agent, lets a watcher tick under way
// finish (a commit included), and exits 0. It starts no commit of its own: a
// platform stop kills the container about 10 s after the signal, and one
// upload to 0G storage alone can take most of that, so a commit begun here
// would be cut off and paid for in vain. What the agent changed since its
// last commit stays on disk instead: the next boot of the same container
// keeps it and the watcher commits it (synced.go, framework.UncommittedKeeper).
//
// Only a sealed that is not PID 1 handles these signals. The images where
// sealed is PID 1 (openclaw, hermes, prime-agent) keep their behaviour.

import (
	"context"
	"os"
	"sync"
	"time"

	"seal-verify/internal/logger"
)

// stopBudget bounds the whole stop sequence. The loader waits longer than
// this before it kills sealed; a platform stop timeout can still end the
// container sooner.
const stopBudget = 90 * time.Second

// stopHooks are run, in registration order, when sealed is asked to stop.
type stopHooks struct {
	mu    sync.Mutex
	hooks []func(context.Context)
}

// sealedStop holds the hooks the boot registers as it brings things up.
var sealedStop stopHooks

func (s *stopHooks) add(fn func(context.Context)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = append(s.hooks, fn)
}

func (s *stopHooks) run(ctx context.Context) {
	s.mu.Lock()
	hooks := make([]func(context.Context), len(s.hooks))
	copy(hooks, s.hooks)
	s.mu.Unlock()
	for _, h := range hooks {
		if ctx.Err() != nil {
			logger.Logf("stop: budget spent; skipping the remaining steps")
			return
		}
		h(ctx)
	}
}

// handleStopSignals runs the stop hooks on the first signal from sigs, then
// persists the log (flush) and calls exit(0). A second signal, or the budget
// running out while a hook still blocks, ends sealed at once.
func handleStopSignals(sigs <-chan os.Signal, hooks *stopHooks, budget time.Duration, flush func(), exit func(int)) {
	sig := <-sigs
	logger.Logf("stop: %v received; stopping the agent (budget %v)", sig, budget)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	done := make(chan struct{})
	go func() {
		hooks.run(ctx)
		close(done)
	}()
	select {
	case <-done:
		logger.Logf("stop: done")
	case s := <-sigs:
		logger.Logf("stop: %v received again; exiting now", s)
	case <-ctx.Done():
		logger.Logf("stop: budget spent; exiting")
	}
	flush()
	exit(0)
}

// What the stop sequence needs from the watcher and the manager.
type (
	stopWatcher interface {
		Stop()
		Done() <-chan struct{}
	}
	stopManager interface {
		Stop(ctx context.Context)
	}
)

// stopAgent is the stop sequence once the agent is up:
//
//  1. Stop the watcher: no new tick starts.
//  2. Stop the framework for good (manager.Stop: a reload or restart under
//     way finishes first, and none follows).
//  3. Wait for a tick under way, so a commit it began can still land.
func stopAgent(ctx context.Context, w stopWatcher, mgr stopManager) {
	w.Stop()
	mgr.Stop(ctx)
	select {
	case <-w.Done():
		return
	default:
	}
	logger.Logf("stop: the agent is stopped; waiting for the watcher's tick under way")
	select {
	case <-w.Done():
	case <-ctx.Done():
		logger.Logf("stop: the watcher's tick outlived the budget; the next boot commits what the agent changed")
	}
}
