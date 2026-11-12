package main

// The layered runtime (sealed/LAYERS.md), sealed's side: which sealed program
// and which official harness package run, once the attestor declares the
// layered flow at GET /provision.
//
// Per layer, the version to run is (LAYERS.md §3.1, §5.3):
//
//   - the owner's pick (versions in the settings document), while the trust
//     registry lists it;
//   - else the version running now, while it is listed;
//   - else, the version running now having been delisted, the newest listed
//     one (the registry's latest).
//
// sealed applies the rule at boot, after every settings push and at every
// heartbeat. At boot the harness also falls back to the package this
// container ran last, then base's. A harness switch restarts the harness on
// the new package and goes back to the previous one when it does not come up.
// A sealed switch hands over to the loader, which goes back to this version
// when the new one does not come up (SEALED_TRIAL, TrialFailedExit).
//
// A version is used only if the trust registry lists it and its bytes hash to
// its name. A version that failed to come up is not tried again in this
// container.
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
	"seal-verify/internal/settings"
)

const (
	// listedTimeout bounds one list read on chain.
	listedTimeout = 15 * time.Second
	// harnessRestartAttempts bounds the restarts a switch makes when another
	// restart (an owner settings push) was under way and its own was skipped.
	harnessRestartAttempts = 5
	// applyTimeout bounds one switch, downloads included.
	applyTimeout = 30 * time.Minute
)

// The trust registry's kinds, as the list reads take them.
var (
	kindSealed  = [32]byte(chain.KindSealed)
	kindHarness = [32]byte(chain.KindHarness)
)

// harnessReadyTimeout is how long a harness restarted on a new package has
// to answer its health check. A var so tests can shorten it.
var harnessReadyTimeout = 3 * time.Minute

// codeLists are the trust registry reads a version must pass (chain.Client).
type codeLists interface {
	Listed(ctx context.Context, kind, hash [32]byte) (bool, error)
	Latest(ctx context.Context, kind [32]byte) ([32]byte, error)
}

// requestSealedSwitch asks the loader to switch (layers.RequestSwitch, which
// signals sealed's parent). A var so tests do not signal the process that
// runs them.
var requestSealedSwitch = layers.RequestSwitch

// layeredRuntime switches versions under the layered flow.
type layeredRuntime struct {
	// sealedHash is this program's hash as the loader verified it.
	sealedHash string
	// lists is nil without a chain client: then no version is confirmed.
	lists codeLists

	// harness, mgr, ready and picks are set once the agent has started
	// (started); harness is nil for adapters that are not packages.
	harness framework.LayeredRuntime
	mgr     interface{ Reload(context.Context) error }
	ready   interface{ Readiness(context.Context) error }
	// picks returns the owner's picks from the settings document in force.
	picks func() settings.Versions

	// busy lets one round of the rule run at a time; a round asked for
	// meanwhile is skipped, and the next heartbeat runs it.
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
	l := &layeredRuntime{sealedHash: cfg.SealedHash}
	if client != nil {
		l.lists = client
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

// switchAfterRefusal hands over to the newest listed sealed version when the
// attestor refused to provision this one because it is no longer listed, and
// reports whether it asked the loader to. There is no settings document
// without provisioning, so no owner pick: the new version applies the pick
// once it has provisioned. The list is read with a chain client of its own.
func switchAfterRefusal(cfg *config.Bootstrap) bool {
	if cfg.SealedHash == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	client, err := chain.Dial(ctx, cfg.ChainRPC, cfg.ContractAddr)
	if err != nil {
		logger.Logf("WARN layers: chain client for the sealed list: %v", err)
		return false
	}
	defer client.Close()
	l := newLayeredRuntime(cfg, client)
	target, ok := l.target(ctx, kindSealed, "", cfg.SealedHash)
	return ok && l.switchSealed(ctx, target)
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

// kindName names a kind in the log.
func kindName(kind [32]byte) string {
	if kind == kindSealed {
		return "sealed"
	}
	return "harness"
}

// listed reads isListed(kind, hash) on chain.
func (l *layeredRuntime) listed(ctx context.Context, kind [32]byte, hash string) (bool, error) {
	if l.lists == nil {
		return false, fmt.Errorf("no chain client")
	}
	ctx, cancel := context.WithTimeout(ctx, listedTimeout)
	defer cancel()
	return l.lists.Listed(ctx, kind, layers.Bytes32(hash))
}

// latest reads latest(kind) on chain: 64 hex, "" when nothing is listed.
func (l *layeredRuntime) latest(ctx context.Context, kind [32]byte) (string, error) {
	if l.lists == nil {
		return "", fmt.Errorf("no chain client")
	}
	ctx, cancel := context.WithTimeout(ctx, listedTimeout)
	defer cancel()
	h, err := l.lists.Latest(ctx, kind)
	if err != nil || h == ([32]byte{}) {
		return "", err
	}
	return fmt.Sprintf("%x", h[:]), nil
}

// failed reports whether hash failed to come up in this container before.
func failed(kind [32]byte, hash string) bool {
	if kind == kindSealed {
		return layers.SealedFailed(hash)
	}
	return layers.HarnessFailed(hash)
}

// target applies the rule to one layer running current: the version to
// switch to, or false to stay. A list that cannot be read keeps current.
func (l *layeredRuntime) target(ctx context.Context, kind [32]byte, pick, current string) (string, bool) {
	name := kindName(kind)
	if p, ok := layers.ParseHash(pick); ok && p != current && !failed(kind, p) {
		listed, err := l.listed(ctx, kind, p)
		if err == nil && listed {
			return p, true
		}
		logger.Logf("layers: the owner's %s pick %s is not confirmed on the %s list (%v); not switching to it", name, shortHex(p), name, err)
	}
	if current != "" {
		listed, err := l.listed(ctx, kind, current)
		if err != nil {
			logger.Logf("WARN layers: the %s list is unreadable (%v); staying on %s", name, err, shortHex(current))
			return "", false
		}
		if listed {
			return "", false
		}
	}
	latest, err := l.latest(ctx, kind)
	switch {
	case err != nil:
		logger.Logf("WARN layers: %s %s is not listed and the newest listed one is unreadable (%v); staying on it", name, shortHex(current), err)
	case latest == "":
		logger.Logf("WARN layers: %s %s is not listed and nothing is; staying on it", name, shortHex(current))
	case latest == current || failed(kind, latest):
		logger.Logf("WARN layers: %s %s is not listed and the newest listed one cannot be used here; staying on it", name, shortHex(current))
	default:
		logger.Logf("layers: %s %s is not listed; moving to the newest listed one, %s", name, shortHex(current), shortHex(latest))
		return latest, true
	}
	return "", false
}

// switchSealed stages sealed version target for the loader and asks it to
// switch; it reports whether it asked. The loader then stops this sealed.
func (l *layeredRuntime) switchSealed(ctx context.Context, target string) bool {
	if l.handedOver || target == l.sealedHash {
		return false
	}
	if layers.SealedFailed(target) {
		logger.Logf("layers: sealed %s failed to come up in this container before; staying on %s", shortHex(target), shortHex(l.sealedHash))
		return false
	}
	ok, err := l.listed(ctx, kindSealed, target)
	if err != nil || !ok {
		logger.Logf("WARN layers: sealed %s is not confirmed on the sealed list (%v); staying on %s", shortHex(target), err, shortHex(l.sealedHash))
		return false
	}
	body, err := layers.FetchArtifact(ctx, target)
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

// chooseHarness picks the package to start at boot: the owner's pick, the
// one this container ran last, the newest listed one, then base's — the
// first one on the harness list that is installed or installs. When none
// can be confirmed (the chain unreachable, nothing listed), it starts the
// one this container ran last, or base's, and says so.
func (l *layeredRuntime) chooseHarness(ctx context.Context, pick, base string) (string, string) {
	sel := layers.LoadHarnessSelection()
	seen := map[string]bool{}
	try := func(c string) (string, bool) {
		h, ok := layers.ParseHash(c)
		if !ok || seen[h] || layers.HarnessFailed(h) {
			return "", false
		}
		seen[h] = true
		ok, err := l.listed(ctx, kindHarness, h)
		if err != nil || !ok {
			logger.Logf("layers: harness %s is not confirmed on the harness list (%v)", shortHex(h), err)
			return "", false
		}
		if err := l.installHarness(ctx, h); err != nil {
			logger.Logf("WARN layers: install harness %s: %v", shortHex(h), err)
			return "", false
		}
		return h, true
	}
	for i := 0; i < 4; i++ {
		var c string
		switch i {
		case 0:
			c = pick
		case 1:
			c = sel.Current
		case 2:
			latest, err := l.latest(ctx, kindHarness)
			if err != nil {
				logger.Logf("layers: the newest listed harness is unreadable: %v", err)
			}
			c = latest
		case 3:
			c = base
		}
		if h, ok := try(c); ok {
			if h != sel.Current {
				l.saveSelection(h, sel.Current)
			}
			return h, layers.HarnessDir(h)
		}
	}
	for _, c := range []string{sel.Current, base} {
		if c != "" && layers.HarnessInstalled(c) {
			logger.Logf("WARN layers: no harness version could be confirmed on the harness list; starting %s, the one this container has", shortHex(c))
			return c, layers.HarnessDir(c)
		}
	}
	logger.Logf("WARN layers: no harness package is installed; starting the image's global install")
	return "", ""
}

// installHarness makes sure the package hash is unpacked, downloading it
// from the artifacts release when it is not.
func (l *layeredRuntime) installHarness(ctx context.Context, hash string) error {
	if layers.HarnessInstalled(hash) {
		return nil
	}
	logger.Logf("layers: downloading harness %s from the artifacts release", shortHex(hash))
	body, err := layers.FetchArtifact(ctx, hash)
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

// started hands the runtime what switching versions needs, once the agent
// has started: the manager, and where the owner's picks are read from.
func (l *layeredRuntime) started(adapter manager.Adapter, mgr *manager.Manager, picks func() settings.Versions) {
	l.ready, l.mgr, l.picks = adapter, mgr, picks
	l.harness, _ = any(adapter).(framework.LayeredRuntime)
}

// recheck applies the rule to both layers while the agent runs: after a
// settings push, and at every heartbeat (a delisting is noticed there).
func (l *layeredRuntime) recheck() {
	if !l.busy.TryLock() {
		return
	}
	defer l.busy.Unlock()
	if l.mgr == nil || l.handedOver {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	var picks settings.Versions
	if l.picks != nil {
		picks = l.picks()
	}
	if s, ok := l.target(ctx, kindSealed, picks.Sealed, l.sealedHash); ok {
		// A new sealed starts its own harness, by the same rule.
		if l.switchSealed(ctx, s) {
			return
		}
	}
	if l.harness == nil {
		return
	}
	if h, ok := l.target(ctx, kindHarness, picks.Harness, l.harness.HarnessHash()); ok {
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
	ok, err := l.listed(ctx, kindHarness, target)
	if err != nil || !ok {
		logger.Logf("WARN layers: harness %s is not confirmed on the harness list (%v); staying on %s", shortHex(target), err, shortHex(prev))
		return
	}
	if err := l.installHarness(ctx, target); err != nil {
		logger.Logf("WARN layers: install harness %s: %v; staying on %s", shortHex(target), err, shortHex(prev))
		return
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
