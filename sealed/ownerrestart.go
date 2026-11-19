package main

// The owner's restarts (POST /_seal/restart, proxy.OwnerRestarter;
// sealed/LAYERS.md §3, §10), for adapters that run a harness package:
//
//   - harness: the manager restarts the harness process, as a settings push
//     does; sealed, the container and the disk stay.
//   - sealed: sealed stops the agent as a stop signal would (shutdown.go) and
//     exits with layers.RestartRequestedExit; the loader starts this version
//     again at once, and does not count it as a crash. Without the layered
//     flow there is no loader to start it again, so the restart is refused.
//     While this boot is still coming up (on trial, its version not yet
//     confirmed to the loader) it is refused too: an exit then would read as
//     a failed version and send the loader back.
//
// Either way what the agent changed since its last commit stays on disk, and
// the next start keeps it (synced.go).

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"seal-verify/internal/layers"
	"seal-verify/internal/logger"
	"seal-verify/internal/proxy"
)

// sealedSettled is set once this boot came up (runMainPipeline).
var sealedSettled atomic.Bool

// exitSealed ends sealed after an owner restart, restartGrace after the
// answer. Vars so tests do not exit or wait.
var (
	exitSealed   = os.Exit
	restartGrace = time.Second
)

// ownerHarnessRestartTimeout bounds one owner-requested harness restart.
const ownerHarnessRestartTimeout = 5 * time.Minute

// ownerRestartsFile, under framework.StateDir, keeps the signed restart
// requests used (proxy.SetOwnerRestartRecord).
const ownerRestartsFile = "owner-restarts.json"

// ownerRestarter is the /_seal/restart applier for a harness-package adapter;
// lr is nil without the layered flow.
func ownerRestarter(mgr interface{ Reload(context.Context) error }, lr *layeredRuntime) proxy.OwnerRestarter {
	return func(layer string) error {
		switch layer {
		case "harness":
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), ownerHarnessRestartTimeout)
				defer cancel()
				logger.Logf("owner restart: restarting the harness")
				if err := mgr.Reload(ctx); err != nil {
					logger.Logf("WARN owner restart: harness: %v", err)
				}
			}()
			return nil
		case "sealed":
			if lr == nil {
				// LEGACY(v1): sealed is PID 1 itself, in an image without the
				// loader.
				return fmt.Errorf("%w: sealed runs without the loader here; stop and start the agent instead", proxy.ErrRestartUnavailable)
			}
			if !sealedSettled.Load() {
				return fmt.Errorf("%w: this sealed is still starting", proxy.ErrRestartBusy)
			}
			go restartSealed()
			return nil
		}
		return fmt.Errorf("%w: %q", proxy.ErrRestartLayer, layer)
	}
}

// restartSealed stops the agent and exits; the loader starts sealed again.
func restartSealed() {
	// Let the 202 reach the owner before the stop begins.
	time.Sleep(restartGrace)
	logger.Logf("owner restart: stopping the agent; the loader starts sealed again")
	ctx, cancel := context.WithTimeout(context.Background(), stopBudget)
	defer cancel()
	sealedStop.run(ctx)
	logger.Flush()
	exitSealed(layers.RestartRequestedExit)
}
