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
// container ran last, then base's; a package that does not start is recorded
// as failed and the next one starts. A harness switch restarts the harness on
// the new package and goes back to the previous one when it does not come up.
// A sealed switch hands over to the loader, which goes back to this version
// when the new one does not come up (SEALED_TRIAL, TrialFailedExit); a boot
// that fails for a reason outside the version exits with TrialTransientExit,
// and the loader starts the same version again later.
//
// A version is used only if the trust registry lists it and its bytes hash to
// its name. A version that failed to come up is not tried again in this
// container. When the loader could not read the sealed list it runs the
// image's own sealed in place of the version it records (SEALED_INSTEAD_OF);
// that sealed applies the rule as the recorded version would, and goes back
// to it once the list confirms it.
//
// LEGACY(pre-1.4.0): without the declaration (an attestor on a chain whose
// AgenticID names no trust registry) the adapter runs base's package and
// nothing is switched (baseHarness).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
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
	// harnessInstallAttempts bounds how often the boot tries to install a
	// listed package when none installs (the artifacts release unreachable).
	harnessInstallAttempts = 3
)

// The trust registry's kinds, as the list reads take them.
var (
	kindSealed  = [32]byte(chain.KindSealed)
	kindHarness = [32]byte(chain.KindHarness)
)

// Waits the layered runtime makes. Vars so tests can shorten them.
var (
	// harnessReadyTimeout is how long a harness restarted on a new package
	// has to answer its health check.
	harnessReadyTimeout = 3 * time.Minute
	// harnessInstallBackoff is the wait before the boot tries the listed
	// packages again, doubling each time.
	harnessInstallBackoff = 30 * time.Second
	// handOverTimeout is how long a sealed that asked the loader to switch
	// waits to be stopped; after that it carries on with this version.
	handOverTimeout = 2 * time.Minute
)

// codeLists are the trust registry reads a version must pass (chain.Client).
type codeLists interface {
	Listed(ctx context.Context, kind, hash [32]byte) (bool, error)
	Latest(ctx context.Context, kind [32]byte) ([32]byte, error)
}

// requestSealedSwitch asks the loader to switch (layers.RequestSwitch, which
// signals sealed's parent). A var so tests do not signal the process that
// runs them.
var requestSealedSwitch = layers.RequestSwitch

// errNoListedHarness: the harness list holds none of the packages this
// container could start. chooseHarness returns it transient: sealed exits for
// the loader to start it again later (exitForRetry), so a version listed
// afterwards is picked up, and a sealed on trial is not blamed for it.
var errNoListedHarness = errors.New("the harness list holds none of the packages this container can start")

// layeredRuntime switches versions under the layered flow.
type layeredRuntime struct {
	// sealedHash is this program's hash as the loader verified it.
	sealedHash string
	// insteadOf is the version this program runs in place of
	// (config.Bootstrap.InsteadOf), "" for none.
	insteadOf string
	// lists is nil without a chain client: then no version is confirmed.
	lists codeLists

	// harness, mgr, ready and picks are set once the agent has started
	// (started); harness is nil for adapters that are not packages.
	harness framework.LayeredRuntime
	mgr     interface{ Reload(context.Context) error }
	ready   interface{ Readiness(context.Context) error }
	// picks returns the owner's picks from the settings document in force.
	picks func() settings.Versions

	// boot is the boot's harness choice (chooseHarness), recorded once the
	// package came up (startFirst).
	boot bootHarness

	// busy lets one round of the rule run at a time; a round asked for
	// meanwhile is skipped, and the next heartbeat runs it.
	busy sync.Mutex
	// handedOver is set once a sealed switch was requested: this sealed is
	// about to be stopped, and switches nothing more. It clears when the
	// loader has not stopped it within handOverTimeout.
	handedOver atomic.Bool
}

// bootHarness is what chooseHarness picked at boot, and from what.
type bootHarness struct {
	pick, base string
	// chosen is the package chosen, "" for none; previous is the one this
	// container ran last.
	chosen, previous string
}

// newLayeredRuntime is the layered runtime of a boot whose provisioning ran
// the layered flow. The loader learns of it, so that from now on it
// restarts a sealed that exits on its own.
func newLayeredRuntime(cfg *config.Bootstrap, client *chain.Client) *layeredRuntime {
	if err := layers.MarkLayered(); err != nil {
		logger.Logf("layers: tell the loader about the layered flow: %v", err)
	}
	// Nothing downloads at this point of a boot: what a stop or a crash cut
	// off mid-download goes.
	layers.CleanCutOffInstalls()
	layers.CleanCutOffStaging()
	l := &layeredRuntime{sealedHash: cfg.SealedHash, insteadOf: cfg.InsteadOf}
	if client != nil {
		l.lists = client
	}
	return l
}

// transientError marks a boot failure whose cause is outside this sealed
// version: an endpoint it could not reach, a download. A version on trial
// that fails so is started again later instead of being gone back from.
type transientError struct{ err error }

func (e transientError) Error() string { return e.err.Error() }
func (e transientError) Unwrap() error { return e.err }

// transient marks err as transientError; nil stays nil.
func transient(err error) error {
	if err == nil {
		return nil
	}
	return transientError{err}
}

// isTransient reports whether err, or an error it wraps, is transientError.
func isTransient(err error) bool {
	var t transientError
	return errors.As(err, &t)
}

// exitSealedProcess ends sealed with a code for the loader. A var so tests do
// not exit.
var exitSealedProcess = os.Exit

// failTrial ends a sealed on trial whose boot failed (cause says why): with
// TrialTransientExit when the cause is outside this version (isTransient), so
// the loader starts it again later, else with TrialFailedExit, which sends
// the loader back to the version it switched from. A sealed not on trial
// keeps serving /log as before.
func failTrial(cfg *config.Bootstrap, what string, cause error) {
	if !cfg.Trial {
		return
	}
	if isTransient(cause) {
		logger.Logf("FAIL layers: this sealed version is on trial and its %s failed for a reason outside it (%v); exiting so the loader starts it again later", what, cause)
		logger.Flush()
		exitSealedProcess(layers.TrialTransientExit)
		return
	}
	logger.Logf("FAIL layers: this sealed version is on trial and its %s failed; exiting so the loader goes back to the previous version", what)
	logger.Flush()
	exitSealedProcess(layers.TrialFailedExit)
}

// exitForRetry ends a sealed whose boot cannot go on now but may later (no
// listed harness package installs): under the layered flow the loader starts
// it again after a wait (TrialTransientExit). Without it the loader would
// stop with sealed, so sealed stays and keeps serving /log.
func exitForRetry(what string, cause error) {
	if !layers.Layered() {
		return
	}
	logger.Logf("FAIL layers: %s: %v; exiting so the loader starts sealed again later", what, cause)
	logger.Flush()
	exitSealedProcess(layers.TrialTransientExit)
}

// switchAfterRefusal hands over to the newest listed sealed version when the
// attestor refused to provision this one because it is no longer listed, and
// waits for the loader to stop this sealed; it returns when there was nothing
// to switch to or the loader did not switch. There is no settings document
// without provisioning, so no owner pick: the new version applies the pick
// once it has provisioned. The list is read with a chain client of its own.
func switchAfterRefusal(cfg *config.Bootstrap) {
	if cfg.SealedHash == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	client, err := chain.Dial(ctx, cfg.ChainRPC, cfg.ContractAddr)
	if err != nil {
		logger.Logf("WARN layers: chain client for the sealed list: %v", err)
		return
	}
	defer client.Close()
	l := newLayeredRuntime(cfg, client)
	if target, ok := l.sealedTarget(ctx, ""); ok && l.switchSealed(ctx, target) {
		l.awaitHandOver()
	}
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

// sealedTarget applies the rule to the sealed layer: the version to switch
// to, or false to stay on this one. A sealed the loader runs in place of
// another (insteadOf) applies the rule as that version would, and asks to go
// back to it once the list confirms it.
func (l *layeredRuntime) sealedTarget(ctx context.Context, pick string) (string, bool) {
	if l.insteadOf == "" || l.insteadOf == l.sealedHash {
		return l.target(ctx, kindSealed, pick, l.sealedHash)
	}
	if t, ok := l.target(ctx, kindSealed, pick, l.insteadOf); ok {
		return t, t != l.sealedHash
	}
	if failed(kindSealed, l.insteadOf) {
		return "", false
	}
	if listed, err := l.listed(ctx, kindSealed, l.insteadOf); err != nil || !listed {
		return "", false
	}
	logger.Logf("layers: sealed %s, which this one runs in place of, is on the sealed list; going back to it", shortHex(l.insteadOf))
	return l.insteadOf, true
}

// switchSealed stages sealed version target for the loader and asks it to
// switch; it reports whether it asked. The loader then stops this sealed.
func (l *layeredRuntime) switchSealed(ctx context.Context, target string) bool {
	if l.handedOver.Load() || target == l.sealedHash {
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
	if layers.SealedStaged(target) {
		logger.Logf("layers: sealed %s is staged already", shortHex(target))
	} else {
		body, err := layers.FetchArtifact(ctx, target)
		if err != nil {
			logger.Logf("WARN layers: fetch sealed %s: %v", shortHex(target), err)
			return false
		}
		err = layers.StageSealed(body, target)
		body.Close()
		if err != nil {
			layers.NoteArtifactError(target, err)
			logger.Logf("WARN layers: stage sealed %s: %v", shortHex(target), err)
			return false
		}
	}
	if err := requestSealedSwitch(target); err != nil {
		logger.Logf("WARN layers: ask the loader to switch to sealed %s: %v", shortHex(target), err)
		return false
	}
	l.handedOver.Store(true)
	logger.Logf("OK   layers: sealed %s staged; the loader switches to it from %s", shortHex(target), shortHex(l.sealedHash))
	time.AfterFunc(handOverTimeout, func() {
		if l.handedOver.CompareAndSwap(true, false) {
			logger.Logf("WARN layers: the loader did not switch to sealed %s within %v; carrying on with %s", shortHex(target), handOverTimeout, shortHex(l.sealedHash))
		}
	})
	return true
}

// awaitHandOver waits, at boot, for the loader to stop this sealed after a
// switch request, and returns once it has not done so within handOverTimeout
// (it refused the switch): the boot then carries on with this version.
func (l *layeredRuntime) awaitHandOver() {
	deadline := time.Now().Add(handOverTimeout + time.Second)
	for l.handedOver.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Second)
	}
	l.handedOver.Store(false)
}

// chooseHarness picks the package to start at boot: the owner's pick, the
// one this container ran last, the newest listed one, then base's — the
// first one the harness list holds that is installed or installs. A package
// the list explicitly does not hold never starts. When the list cannot be
// read for the one this container ran last, or for base's, that one starts
// (installed already), and the log says so; when it cannot be read and
// neither is there, the error is transient. When listed packages exist but
// none installs (the artifacts release unreachable), it tries again a few
// times, then returns a transient error. It records nothing: startFirst
// does, once the package came up.
func (l *layeredRuntime) chooseHarness(ctx context.Context, pick, base string) (string, string, error) {
	sel := layers.LoadHarnessSelection()
	l.boot = bootHarness{pick: pick, base: base, previous: sel.Current}
	wait := harnessInstallBackoff
	for attempt := 1; ; attempt++ {
		hash, dir, installErr, err := l.chooseHarnessOnce(ctx, pick, base, sel)
		if err != nil {
			return "", "", err
		}
		if installErr == nil {
			l.boot.chosen = hash
			return hash, dir, nil
		}
		if attempt >= harnessInstallAttempts {
			return "", "", transient(fmt.Errorf("no listed harness package installs: %w", installErr))
		}
		logger.Logf("WARN layers: no listed harness package installs (%v); trying again in %v", installErr, wait)
		select {
		case <-ctx.Done():
			return "", "", transient(ctx.Err())
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// chooseHarnessOnce is one round of chooseHarness. installErr is set when
// listed packages exist and none installed; err when there is nothing this
// container may start.
func (l *layeredRuntime) chooseHarnessOnce(ctx context.Context, pick, base string, sel layers.HarnessSelection) (hash, dir string, installErr, err error) {
	seen := map[string]bool{}
	// unread holds the packages whose list answer could not be had.
	unread := map[string]bool{}
	try := func(c string) (string, bool) {
		h, ok := layers.ParseHash(c)
		if !ok || seen[h] || layers.HarnessFailed(h) {
			return "", false
		}
		seen[h] = true
		listed, err := l.listed(ctx, kindHarness, h)
		if err != nil {
			logger.Logf("layers: harness %s: the harness list is unreadable (%v)", shortHex(h), err)
			unread[h] = true
			return "", false
		}
		if !listed {
			logger.Logf("layers: harness %s is not on the harness list; not starting it", shortHex(h))
			return "", false
		}
		if err := l.installHarness(ctx, h); err != nil {
			logger.Logf("WARN layers: install harness %s: %v", shortHex(h), err)
			installErr = err
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
			return h, layers.HarnessDir(h), nil, nil
		}
	}
	if installErr != nil {
		return "", "", installErr, nil
	}
	// unread holds no failed package: try skips those first.
	for _, c := range []string{sel.Current, base} {
		if c != "" && unread[c] && layers.HarnessInstalled(c) {
			logger.Logf("WARN layers: the harness list cannot be read; starting %s, the one this container has", shortHex(c))
			return c, layers.HarnessDir(c), nil, nil
		}
	}
	if len(unread) > 0 {
		return "", "", nil, transient(errors.New("the harness list cannot be read for the packages this container could start"))
	}
	return "", "", nil, transient(errNoListedHarness)
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
		layers.NoteArtifactError(hash, err)
		return err
	}
	logger.Logf("OK   layers: harness %s installed at %s", shortHex(hash), layers.HarnessDir(hash))
	return nil
}

// startFirst makes the agent's first start (start) on the package chosen at
// boot. When that package does not start (framework.ErrHarnessDidNotStart),
// it is recorded as failed in this container, what it left is stopped
// (stop), and the boot's choice is made again without it; the start fails
// only when base's package fails too. The choice is recorded once a package
// came up (LAYERS.md §5.3 item 3).
func (l *layeredRuntime) startFirst(ctx context.Context, h framework.LayeredRuntime, start func() error, stop func(context.Context)) error {
	for {
		err := start()
		chosen := l.boot.chosen
		if err == nil {
			if chosen != "" && chosen != l.boot.previous {
				l.saveSelection(chosen, l.boot.previous)
			}
			return nil
		}
		if !errors.Is(err, framework.ErrHarnessDidNotStart) || chosen == "" || chosen == l.boot.base {
			return err
		}
		logger.Logf("FAIL layers: harness %s did not start (%v); starting the next version", shortHex(chosen), err)
		layers.MarkHarnessFailed(chosen)
		stop(ctx)
		hash, dir, cerr := l.chooseHarness(ctx, l.boot.pick, l.boot.base)
		if cerr != nil {
			return fmt.Errorf("%w; and then: %w", err, cerr)
		}
		if hash == chosen {
			return err
		}
		h.UseHarness(hash, dir)
	}
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
	if l.mgr == nil || l.handedOver.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	var picks settings.Versions
	if l.picks != nil {
		picks = l.picks()
	}
	if s, ok := l.sealedTarget(ctx, picks.Sealed); ok {
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
	l.pruneLocked(picks)
}

// prune removes the versions nothing here runs (pruneLocked), unless a round
// of the rule is under way.
func (l *layeredRuntime) prune() {
	if !l.busy.TryLock() {
		return
	}
	defer l.busy.Unlock()
	var picks settings.Versions
	if l.picks != nil {
		picks = l.picks()
	}
	l.pruneLocked(picks)
}

// pruneLocked removes the staged sealed programs and the unpacked packages
// no version this container may run names, and what a download or an
// install cut off left behind. l.busy must be held; nothing is removed while
// a sealed switch is asked for.
func (l *layeredRuntime) pruneLocked(picks settings.Versions) {
	if l.handedOver.Load() {
		return
	}
	layers.PruneStaged(l.sealedHash, l.insteadOf, picks.Sealed)
	keep := []string{picks.Harness}
	if l.harness != nil {
		keep = append(keep, l.harness.HarnessHash())
	}
	sel := layers.LoadHarnessSelection()
	keep = append(keep, sel.Current, sel.Previous)
	layers.PrunePackages(keep...)
}

// switchHarness restarts the harness on package target, and goes back to
// the package it ran when that one does not come up. A restart that did not
// happen because the agent is stopping records nothing against target.
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
		l.harness.UseHarness(prev, harnessDirOf(prev))
		if errors.Is(err, errNotRestarted) {
			logger.Logf("WARN layers: the harness was not restarted on %s (%v); staying on %s", shortHex(target), err, shortHex(prev))
			return
		}
		logger.Logf("FAIL layers: harness %s did not come up (%v); going back to %s", shortHex(target), err, shortHex(prev))
		layers.MarkHarnessFailed(target)
		if err := l.restartOn(ctx, prev); err != nil {
			logger.Logf("FAIL layers: harness %s did not come back either: %v", shortHex(prev), err)
		}
		return
	}
	l.saveSelection(target, prev)
	logger.Logf("OK   layers: harness %s running", shortHex(target))
}

// errNotRestarted: a harness restart did not happen for a reason that says
// nothing about the package (the agent stopping, the round's time spent).
var errNotRestarted = errors.New("the harness was not restarted")

// restartOn restarts the harness until the process running is package
// hash, then waits for its health check. errNotRestarted when the restart
// itself did not happen.
func (l *layeredRuntime) restartOn(ctx context.Context, hash string) error {
	for i := 0; i < harnessRestartAttempts && l.harness.HarnessHash() != hash; i++ {
		if i > 0 {
			// A restart already under way skipped this one.
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %w", errNotRestarted, ctx.Err())
			case <-time.After(5 * time.Second):
			}
		}
		if err := l.mgr.Reload(ctx); err != nil {
			if ctx.Err() != nil || errors.Is(err, manager.ErrStopped) {
				return fmt.Errorf("%w: %w", errNotRestarted, err)
			}
			return err
		}
	}
	if l.harness.HarnessHash() != hash {
		return fmt.Errorf("%w on %s (another restart kept running; the agent may be stopping)", errNotRestarted, shortHex(hash))
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
			return fmt.Errorf("%w: %w", errNotRestarted, ctx.Err())
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
// LEGACY(pre-1.4.0) without the layered flow; LEGACY(v1) for the global
// install.
func baseHarness() (string, string) {
	base, err := layers.BaseHarness()
	if err != nil {
		logger.Logf("layers: no harness package named by %s/base (%v); starting the image's global install", layers.PackagesDir, err)
		return "", ""
	}
	return base, layers.HarnessDir(base)
}
