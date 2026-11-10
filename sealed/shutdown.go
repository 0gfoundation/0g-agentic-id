package main

// Graceful stop, for sealed running under the loader (cmd/loader).
//
// On SIGTERM or SIGINT sealed stops the agent and commits what changed since
// the watcher's last tick, then exits 0. Without it, a stop loses the agent's
// edits, made after the last commit, to what is already on chain (the persona,
// a committed skill): the next boot writes the chain version back over them.
// A file the agent added survives on disk and is committed after the restart.
//
// Only a sealed that is not PID 1 handles these signals. In the images where
// sealed is PID 1 (openclaw, hermes, prime-agent) the kernel drops a signal
// PID 1 has no handler for, and they keep today's behaviour: the platform
// kills the container when its stop timeout runs out.

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
	logger.Logf("stop: %v received; stopping the agent and committing pending iData (budget %v)", sig, budget)
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

// What the stop sequence needs from the watcher, the manager and the
// uploader.
type (
	stopWatcher interface {
		Stop()
		Done() <-chan struct{}
		Final(ctx context.Context, onDrift func(plaintexts map[string][]byte, drifted []string))
	}
	stopManager interface {
		Stop(ctx context.Context)
	}
	stopCommitter interface {
		Apply(ctx context.Context, plaintexts map[string][]byte) error
	}
)

// stopAgentAndCommit is the stop sequence once the agent is up:
//
//  1. Stop the watcher and wait for its current tick, so no drift handler
//     (which may reload the framework) runs after this point.
//  2. Stop the framework, so the disk stops changing.
//  3. Run one last tick and commit any drift it finds, unless the agent now
//     belongs to another owner.
func stopAgentAndCommit(ctx context.Context, w stopWatcher, mgr stopManager, upload stopCommitter, ownerLocked func() bool) {
	w.Stop()
	select {
	case <-w.Done():
	case <-ctx.Done():
		logger.Logf("stop: the watcher's tick in progress outlived the budget; nothing more is committed")
		return
	}
	mgr.Stop(ctx)
	if ownerLocked() {
		logger.Logf("stop: the agent belongs to another owner now; nothing is committed")
		return
	}
	w.Final(ctx, func(plaintexts map[string][]byte, drifted []string) {
		logger.Logf("stop: committing %v", drifted)
		if err := upload.Apply(ctx, plaintexts); err != nil {
			logger.Logf("stop: commit failed: %v", err)
			return
		}
		logger.Logf("stop: committed")
	})
}
