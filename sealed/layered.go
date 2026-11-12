package main

// The layered runtime (sealed/LAYERS.md), sealed's side: which harness
// official version package the 0g-harness adapter runs, and, once the
// attestor declares the layered flow at GET /provision, switching the sealed
// and harness versions it targets:
//
//   - at boot, before the agent starts: a sealed target other than this
//     program is staged for the loader, which stops this sealed and starts
//     that one; the harness runs the targeted package, or the one this
//     container ran last, or base's, the first of them listed in
//     validHarnessHashes (installed from the attestor first when needed);
//   - while running: the same, for a target named in a reply to a status
//     report. A harness switch restarts the harness on the new package and
//     goes back to the previous one when it does not come up. A sealed
//     switch hands over to the loader, which goes back to this version when
//     the new one does not come up (SEALED_TRIAL, TrialFailedExit).
//
// A version is used only if AgenticID lists it (isValidSealedHash,
// isValidHarnessHash) and its bytes hash to its name. A version that failed
// to come up is not tried again in this container.
//
// Without the declaration, the adapter runs base's package and nothing is
// switched.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"seal-verify/internal/chain"
	"seal-verify/internal/config"
	"seal-verify/internal/framework"
	"seal-verify/internal/layers"
	"seal-verify/internal/logger"
	"seal-verify/internal/manager"
)

const (
	// listedTimeout bounds one allowlist read on chain.
	listedTimeout = 15 * time.Second
	// harnessRestartAttempts bounds the restarts a switch makes when another
	// restart (an owner settings push) was under way and its own was skipped.
	harnessRestartAttempts = 5
	// applyTimeout bounds one switch, downloads included.
	applyTimeout = 30 * time.Minute
)

// harnessReadyTimeout is how long a harness restarted on a new package has
// to answer its health check. A var so tests can shorten it.
var harnessReadyTimeout = 3 * time.Minute

// allowlists are the AgenticID reads a version must pass (chain.Client).
type allowlists interface {
	IsValidSealedHash(ctx context.Context, hash [32]byte) (bool, error)
	IsValidHarnessHash(ctx context.Context, hash [32]byte) (bool, error)
}

// requestSealedSwitch asks the loader to switch (layers.RequestSwitch, which
// signals sealed's parent). A var so tests do not signal the process that
// runs them.
var requestSealedSwitch = layers.RequestSwitch

// layeredRuntime switches versions under the layered flow.
type layeredRuntime struct {
	attestorURL string
	// sealedHash is this program's hash as the loader verified it.
	sealedHash string
	// allow is nil without a chain client: then no version is confirmed.
	allow allowlists

	// harness, mgr and ready are set once the agent has started (started);
	// harness is nil for adapters that are not packages.
	harness framework.LayeredRuntime
	mgr     interface{ Reload(context.Context) error }
	ready   interface{ Readiness(context.Context) error }

	// busy lets one switch run at a time; a target arriving meanwhile waits
	// for the next status reply.
	busy sync.Mutex
	// handedOver is set once a sealed switch was requested: this sealed is
	// about to be stopped, and switches nothing more.
	handedOver bool
}

// newLayeredRuntime is the layered runtime of a boot whose provisioning ran
// the layered flow. The loader learns of it, so that from now on it
// restarts a sealed that exits on its own.
func newLayeredRuntime(cfg *config.Bootstrap, client *chain.Client) *layeredRuntime {
	if err := layers.MarkLayered(); err != nil {
		logger.Logf("layers: tell the loader about the layered flow: %v", err)
	}
	l := &layeredRuntime{attestorURL: cfg.AttestorURL, sealedHash: cfg.SealedHash}
	if client != nil {
		l.allow = client
	}
	return l
}

// failTrial ends a sealed on trial whose boot failed, with the exit code
// that sends the loader back to the version it switched from. A sealed not
// on trial keeps serving /log as before.
func failTrial(cfg *config.Bootstrap, what string) {
	if !cfg.Trial {
		return
	}
	logger.Logf("FAIL layers: this sealed version is on trial and its %s failed; exiting so the loader goes back to the previous version", what)
	logger.Flush()
	os.Exit(layers.TrialFailedExit)
}

// switchAfterRefusal hands over to the sealed version the attestor named
// when provisioning this one failed, and reports whether it asked the
// loader to. The allowlist is read on chain with a client of its own: there
// is no agent key, and no chain bootstrap, without provisioning.
func switchAfterRefusal(cfg *config.Bootstrap, target string) bool {
	t, ok := layers.ParseHash(target)
	if !ok || cfg.SealedHash == "" || t == cfg.SealedHash {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	client, err := chain.Dial(ctx, cfg.ChainRPC, cfg.ContractAddr)
	if err != nil {
		logger.Logf("WARN layers: chain client for the sealed target: %v", err)
		return false
	}
	defer client.Close()
	return newLayeredRuntime(cfg, client).switchSealed(ctx, t)
}

// confirmTrial tells the loader that this version came up.
func confirmTrial(cfg *config.Bootstrap) {
	if !cfg.Trial {
		return
	}
	if err := layers.Confirm(cfg.SealedHash); err != nil {
		logger.Logf("WARN layers: confirm this sealed version to the loader: %v", err)
		return
	}
	logger.Logf("OK   layers: sealed %s confirmed to the loader", shortHex(cfg.SealedHash))
}

// listedSealed and listedHarness read the allowlists on chain.
func (l *layeredRuntime) listedSealed(ctx context.Context, hash string) (bool, error) {
	if l.allow == nil {
		return false, fmt.Errorf("no chain client")
	}
	ctx, cancel := context.WithTimeout(ctx, listedTimeout)
	defer cancel()
	return l.allow.IsValidSealedHash(ctx, layers.Bytes32(hash))
}

func (l *layeredRuntime) listedHarness(ctx context.Context, hash string) (bool, error) {
	if l.allow == nil {
		return false, fmt.Errorf("no chain client")
	}
	ctx, cancel := context.WithTimeout(ctx, listedTimeout)
	defer cancel()
	return l.allow.IsValidHarnessHash(ctx, layers.Bytes32(hash))
}

// switchSealed stages sealed version target for the loader and asks it to
// switch; it reports whether it asked. The loader then stops this sealed.
func (l *layeredRuntime) switchSealed(ctx context.Context, target string) bool {
	if l.handedOver || target == l.sealedHash {
		return false
	}
	if layers.SealedFailed(target) {
		logger.Logf("layers: sealed target %s failed to come up in this container before; staying on %s", shortHex(target), shortHex(l.sealedHash))
		return false
	}
	ok, err := l.listedSealed(ctx, target)
	if err != nil || !ok {
		logger.Logf("WARN layers: sealed target %s is not confirmed in validSealedHashes (%v); staying on %s", shortHex(target), err, shortHex(l.sealedHash))
		return false
	}
	body, err := layers.FetchArtifact(ctx, l.attestorURL, target)
	if err != nil {
		logger.Logf("WARN layers: fetch sealed %s: %v", shortHex(target), err)
		return false
	}
	err = layers.StageSealed(body, target)
	body.Close()
	if err != nil {
		logger.Logf("WARN layers: stage sealed %s: %v", shortHex(target), err)
		return false
	}
	if err := requestSealedSwitch(target); err != nil {
		logger.Logf("WARN layers: ask the loader to switch to sealed %s: %v", shortHex(target), err)
		return false
	}
	l.handedOver = true
	logger.Logf("OK   layers: sealed %s staged; the loader switches to it from %s", shortHex(target), shortHex(l.sealedHash))
	return true
}

// chooseHarness picks the package to start at boot: the target, the one
// this container ran last, then base's — the first one listed in
// validHarnessHashes that is installed or installs. When none can be
// confirmed (the chain unreachable, nothing listed), it starts the one this
// container ran last, or base's, and says so.
func (l *layeredRuntime) chooseHarness(ctx context.Context, target, base string) (string, string) {
	sel := layers.LoadHarnessSelection()
	var candidates []string
	seen := map[string]bool{}
	for _, c := range []string{target, sel.Current, base} {
		if h, ok := layers.ParseHash(c); ok && !seen[h] && !layers.HarnessFailed(h) {
			seen[h] = true
			candidates = append(candidates, h)
		}
	}
	for _, c := range candidates {
		ok, err := l.listedHarness(ctx, c)
		if err != nil || !ok {
			logger.Logf("layers: harness %s is not confirmed in validHarnessHashes (%v)", shortHex(c), err)
			continue
		}
		if err := l.installHarness(ctx, c); err != nil {
			logger.Logf("WARN layers: install harness %s: %v", shortHex(c), err)
			continue
		}
		if c != sel.Current {
			l.saveSelection(c, sel.Current)
		}
		return c, layers.HarnessDir(c)
	}
	for _, c := range []string{sel.Current, base} {
		if c != "" && layers.HarnessInstalled(c) {
			logger.Logf("WARN layers: no harness version could be confirmed in validHarnessHashes; starting %s, the one this container has", shortHex(c))
			return c, layers.HarnessDir(c)
		}
	}
	logger.Logf("WARN layers: no harness package is installed; starting the image's global install")
	return "", ""
}

// installHarness makes sure the package hash is unpacked, fetching it from
// the attestor when it is not.
func (l *layeredRuntime) installHarness(ctx context.Context, hash string) error {
	if layers.HarnessInstalled(hash) {
		return nil
	}
	logger.Logf("layers: fetching harness %s from the attestor", shortHex(hash))
	body, err := layers.FetchArtifact(ctx, l.attestorURL, hash)
	if err != nil {
		return err
	}
	defer body.Close()
	if err := layers.InstallHarness(body, hash); err != nil {
		return err
	}
	logger.Logf("OK   layers: harness %s installed at %s", shortHex(hash), layers.HarnessDir(hash))
	return nil
}

// saveSelection records which package runs.
func (l *layeredRuntime) saveSelection(current, previous string) {
	if err := layers.SaveHarnessSelection(layers.HarnessSelection{Current: current, Previous: previous}); err != nil {
		logger.Logf("WARN layers: record the harness selection: %v", err)
	}
}

// started hands the runtime what switching the harness needs, once the
// agent has started.
func (l *layeredRuntime) started(adapter manager.Adapter, mgr *manager.Manager) {
	l.ready, l.mgr = adapter, mgr
	l.harness, _ = any(adapter).(framework.LayeredRuntime)
}

// apply acts on the versions a status reply names (report.SetTargetsHandler).
func (l *layeredRuntime) apply(t layers.Targets) {
	if !l.busy.TryLock() {
		return
	}
	defer l.busy.Unlock()
	if l.mgr == nil || l.handedOver {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	if s, ok := layers.ParseHash(t.Sealed); ok && s != l.sealedHash {
		// A new sealed starts its own harness, at its own target.
		if l.switchSealed(ctx, s) {
			return
		}
	}
	if h, ok := layers.ParseHash(t.Harness); ok && l.harness != nil && h != l.harness.HarnessHash() {
		l.switchHarness(ctx, h)
	}
}

// switchHarness restarts the harness on package target, and goes back to
// the package it ran when that one does not come up.
func (l *layeredRuntime) switchHarness(ctx context.Context, target string) {
	if layers.HarnessFailed(target) {
		return
	}
	prev := l.harness.HarnessHash()
	ok, err := l.listedHarness(ctx, target)
	if err != nil || !ok {
		logger.Logf("WARN layers: harness target %s is not confirmed in validHarnessHashes (%v); staying on %s", shortHex(target), err, shortHex(prev))
		return
	}
	if err := l.installHarness(ctx, target); err != nil {
		logger.Logf("WARN layers: install harness %s: %v; staying on %s", shortHex(target), err, shortHex(prev))
		return
	}
	if v, ok := l.harness.(framework.RuntimePackageValidator); ok {
		if err := v.ValidateRuntimePackage(layers.HarnessDir(target)); err != nil {
			logger.Logf("WARN layers: incompatible harness target (%v); staying on %s", err, shortHex(prev))
			return
		}
	}
	logger.Logf("layers: switching the harness from %s to %s", shortHex(prev), shortHex(target))
	l.harness.UseHarness(target, layers.HarnessDir(target))
	if err := l.restartOn(ctx, target); err != nil {
		logger.Logf("FAIL layers: harness %s did not come up (%v); going back to %s", shortHex(target), err, shortHex(prev))
		layers.MarkHarnessFailed(target)
		l.harness.UseHarness(prev, harnessDirOf(prev))
		if err := l.restartOn(ctx, prev); err != nil {
			logger.Logf("FAIL layers: harness %s did not come back either: %v", shortHex(prev), err)
		}
		return
	}
	l.saveSelection(target, prev)
	logger.Logf("OK   layers: harness %s running", shortHex(target))
}

// restartOn restarts the harness until the process running is package
// hash, then waits for its health check.
func (l *layeredRuntime) restartOn(ctx context.Context, hash string) error {
	for i := 0; i < harnessRestartAttempts && l.harness.HarnessHash() != hash; i++ {
		if i > 0 {
			// A restart already under way skipped this one.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
		if err := l.mgr.Reload(ctx); err != nil {
			return err
		}
	}
	if l.harness.HarnessHash() != hash {
		return fmt.Errorf("the harness was not restarted on %s", shortHex(hash))
	}
	deadline := time.Now().Add(harnessReadyTimeout)
	for {
		err := l.ready.Readiness(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// harnessDirOf is the directory of package hash, "" for none (the image's
// global install).
func harnessDirOf(hash string) string {
	if hash == "" {
		return ""
	}
	return layers.HarnessDir(hash)
}

// baseHarness is the package the adapter starts on without the layered
// flow: base's, or none (the image's global install) when base names none.
func baseHarness() (string, string) {
	base, err := layers.BaseHarness()
	if err != nil {
		logger.Logf("layers: no harness package named by %s/base (%v); starting the image's global install", layers.PackagesDir, err)
		return "", ""
	}
	return base, layers.HarnessDir(base)
}
