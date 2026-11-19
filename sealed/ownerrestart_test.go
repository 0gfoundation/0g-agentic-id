package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"seal-verify/internal/layers"
	"seal-verify/internal/proxy"
)

type countingReloader struct{ reloads chan struct{} }

func (r countingReloader) Reload(context.Context) error {
	r.reloads <- struct{}{}
	return nil
}

func TestOwnerRestarterHarnessReloads(t *testing.T) {
	r := countingReloader{reloads: make(chan struct{}, 1)}
	if err := ownerRestarter(r, nil)("harness"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.reloads:
	case <-time.After(5 * time.Second):
		t.Fatal("the harness was not restarted")
	}
}

func TestOwnerRestarterSealedRefusals(t *testing.T) {
	r := countingReloader{reloads: make(chan struct{}, 1)}
	if err := ownerRestarter(r, nil)("sealed"); !errors.Is(err, proxy.ErrRestartUnavailable) {
		t.Fatalf("without the layered flow: %v", err)
	}
	sealedSettled.Store(false)
	if err := ownerRestarter(r, &layeredRuntime{})("sealed"); !errors.Is(err, proxy.ErrRestartBusy) {
		t.Fatalf("still starting: %v", err)
	}
	if err := ownerRestarter(r, &layeredRuntime{})("container"); !errors.Is(err, proxy.ErrRestartLayer) {
		t.Fatalf("unknown layer: %v", err)
	}
}

// Once up, a sealed restart runs the stop hooks, then exits with
// RestartRequestedExit for the loader to start sealed again at once.
func TestOwnerRestarterSealedStopsThenExits(t *testing.T) {
	oldExit, oldGrace, oldHooks := exitSealed, restartGrace, sealedStop.hooks
	exited := make(chan int, 1)
	exitSealed, restartGrace = func(code int) { exited <- code }, 0
	stopped := false
	sealedStop.hooks = nil
	sealedStop.add(func(context.Context) { stopped = true })
	t.Cleanup(func() {
		exitSealed, restartGrace, sealedStop.hooks = oldExit, oldGrace, oldHooks
		sealedSettled.Store(false)
	})

	sealedSettled.Store(true)
	if err := ownerRestarter(countingReloader{reloads: make(chan struct{}, 1)}, &layeredRuntime{})("sealed"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-exited:
		if code != layers.RestartRequestedExit || !stopped {
			t.Fatalf("exit %d, stop hooks ran: %v", code, stopped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sealed did not exit")
	}
}
