package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/config"
	"seal-verify/internal/framework"
	"seal-verify/internal/layers"
	"seal-verify/internal/manager"
	"seal-verify/internal/settings"
)

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// testPackage is a minimal harness package holding one file.
func testPackage(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "package.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// layeredEnv points every layered path at temp dirs and serves artifacts
// from a fake release.
type layeredEnv struct {
	artifacts map[string][]byte
}

func newLayeredEnv(t *testing.T) *layeredEnv {
	t.Helper()
	oldP, oldL, oldS, oldReq, oldA := layers.PackagesDir, layers.LoaderDir, framework.StateDir, requestSealedSwitch, layers.ArtifactsURL
	layers.PackagesDir = filepath.Join(t.TempDir(), "0g-harness")
	layers.LoaderDir = filepath.Join(t.TempDir(), "loader")
	framework.StateDir = t.TempDir()
	t.Cleanup(func() {
		layers.PackagesDir, layers.LoaderDir, framework.StateDir, requestSealedSwitch, layers.ArtifactsURL = oldP, oldL, oldS, oldReq, oldA
	})
	env := &layeredEnv{artifacts: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := env.artifacts[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	layers.ArtifactsURL = srv.URL
	return env
}

// serve makes an artifact available and returns its hash.
func (e *layeredEnv) serve(b []byte) string {
	h := hexSum(b)
	e.artifacts[h] = b
	return h
}

// installBase installs a package as base's.
func (e *layeredEnv) installBase(t *testing.T, pkg []byte) string {
	t.Helper()
	h := hexSum(pkg)
	if err := layers.InstallHarness(layers.VerifyingReader(nopCloser{bytes.NewReader(pkg)}, h), h); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layers.PackagesDir, "base"), []byte(h), 0o644); err != nil {
		t.Fatal(err)
	}
	return h
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// fakeLists is a trust registry holding what it lists; latest names each
// kind's newest listed hash. unreadable fails every read, unreadableFor the
// reads of the hashes it holds.
type fakeLists struct {
	sealed, harness             map[string]bool
	latestSealed, latestHarness string
	unreadable                  bool
	unreadableFor               map[string]bool
}

func (f fakeLists) Listed(_ context.Context, kind, h [32]byte) (bool, error) {
	if f.unreadable || f.unreadableFor[hex.EncodeToString(h[:])] {
		return false, errors.New("rpc down")
	}
	if kind == kindSealed {
		return f.sealed[hex.EncodeToString(h[:])], nil
	}
	return f.harness[hex.EncodeToString(h[:])], nil
}

func (f fakeLists) Latest(_ context.Context, kind [32]byte) ([32]byte, error) {
	if f.unreadable {
		return [32]byte{}, errors.New("rpc down")
	}
	if kind == kindSealed {
		return layers.Bytes32(f.latestSealed), nil
	}
	return layers.Bytes32(f.latestHarness), nil
}

func picksOf(v settings.Versions) func() settings.Versions {
	return func() settings.Versions { return v }
}

func TestChooseHarnessTakesTheListedPick(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	target := env.serve(testPackage(t, "target"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{base: true, target: true}, latestHarness: base}}

	hash, dir, err := l.chooseHarness(context.Background(), "0x"+target, base)
	if err != nil || hash != target || dir != layers.HarnessDir(target) || !layers.HarnessInstalled(target) {
		t.Fatalf("chose %s at %s (%v)", hash, dir, err)
	}
	// Recorded only once it came up (startFirst).
	if got := layers.LoadHarnessSelection(); got.Current != "" {
		t.Fatalf("selection %+v before the package came up", got)
	}
}

func TestChooseHarnessSkipsWhatIsNotListed(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	target := env.serve(testPackage(t, "target"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{base: true}}}

	if hash, _, err := l.chooseHarness(context.Background(), "0x"+target, base); hash != base || err != nil {
		t.Fatalf("chose %s (%v), want base %s", hash, err, base)
	}
	if layers.HarnessInstalled(target) {
		t.Fatal("an unlisted pick was installed")
	}
}

// A fresh container with no pick runs the newest listed package, not base's.
func TestChooseHarnessFreshContainerTakesTheNewestListed(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	newest := env.serve(testPackage(t, "newest"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{base: true, newest: true}, latestHarness: newest}}
	if hash, _, err := l.chooseHarness(context.Background(), "", base); hash != newest || err != nil {
		t.Fatalf("chose %s (%v), want the newest listed %s", hash, err, newest)
	}
}

// Without a chain to confirm anything, the package this container has runs.
func TestChooseHarnessUnconfirmedRunsWhatIsInstalled(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	l := &layeredRuntime{}
	if hash, _, err := l.chooseHarness(context.Background(), "0x"+env.serve(testPackage(t, "target")), base); hash != base || err != nil {
		t.Fatalf("chose %s (%v), want base %s", hash, err, base)
	}
}

// fakeHarness runs whatever UseHarness set once fakeReloader restarts it.
type fakeHarness struct{ next, running string }

func (f *fakeHarness) UseHarness(hash, _ string)         { f.next = hash }
func (f *fakeHarness) HarnessHash() string               { return f.running }
func (f *fakeHarness) InferenceTarget() (string, string) { return "", "" }

type fakeReloader struct {
	h       *fakeHarness
	reloads int
}

func (m *fakeReloader) Reload(context.Context) error {
	m.reloads++
	m.h.running = m.h.next
	return nil
}

// fakeReady fails the health check of one package.
type fakeReady struct {
	h   *fakeHarness
	bad string
}

func (r fakeReady) Readiness(context.Context) error {
	if r.h.running == r.bad {
		return errors.New("not ready")
	}
	return nil
}

// switchFixture runs base's package, with target served and both listed.
func switchFixture(t *testing.T, bad bool) (*layeredRuntime, *fakeHarness, string, string) {
	t.Helper()
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	target := env.serve(testPackage(t, "target"))
	h := &fakeHarness{next: base, running: base}
	ready := fakeReady{h: h}
	if bad {
		ready.bad = target
	}
	old := harnessReadyTimeout
	harnessReadyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { harnessReadyTimeout = old })
	own := strings.Repeat("aa", 32)
	l := &layeredRuntime{sealedHash: own,
		lists:   fakeLists{sealed: map[string]bool{own: true}, harness: map[string]bool{base: true, target: true}, latestHarness: target},
		harness: h, mgr: &fakeReloader{h: h}, ready: ready, picks: picksOf(settings.Versions{})}
	return l, h, base, target
}

func TestRecheckSwitchesTheHarnessToThePick(t *testing.T) {
	l, h, base, target := switchFixture(t, false)
	l.picks = picksOf(settings.Versions{Harness: "0x" + target})
	l.recheck()
	if h.running != target {
		t.Fatalf("running %s, want %s", h.running, target)
	}
	if got := layers.LoadHarnessSelection(); got.Current != target || got.Previous != base {
		t.Fatalf("selection %+v", got)
	}
}

// No pick, the running package still listed: a newer listed one does not
// move it (only a delisting does).
func TestRecheckStaysWhileTheRunningVersionIsListed(t *testing.T) {
	l, h, base, _ := switchFixture(t, false)
	l.recheck()
	if h.running != base || l.mgr.(*fakeReloader).reloads != 0 {
		t.Fatalf("running %s after %d reloads, want base %s untouched", h.running, l.mgr.(*fakeReloader).reloads, base)
	}
}

func TestRecheckMovesOffADelistedHarness(t *testing.T) {
	l, h, base, target := switchFixture(t, false)
	lists := l.lists.(fakeLists)
	delete(lists.harness, base)
	l.lists = lists
	l.recheck()
	if h.running != target {
		t.Fatalf("running %s, want the newest listed %s", h.running, target)
	}
}

// A pick the registry does not list is not switched to.
func TestRecheckIgnoresAnUnlistedPick(t *testing.T) {
	l, h, base, _ := switchFixture(t, false)
	l.picks = picksOf(settings.Versions{Harness: "0x" + strings.Repeat("cd", 32)})
	l.recheck()
	if h.running != base {
		t.Fatalf("running %s, want base %s", h.running, base)
	}
}

// A list that cannot be read keeps what runs.
func TestRecheckKeepsWhatRunsWhenTheListIsUnreadable(t *testing.T) {
	l, h, base, _ := switchFixture(t, false)
	l.lists = fakeLists{unreadable: true}
	l.recheck()
	if h.running != base {
		t.Fatalf("running %s, want base %s", h.running, base)
	}
}

func TestRecheckGoesBackWhenTheHarnessDoesNotComeUp(t *testing.T) {
	l, h, base, target := switchFixture(t, true)
	l.picks = picksOf(settings.Versions{Harness: "0x" + target})
	l.recheck()
	if h.running != base {
		t.Fatalf("running %s, want base %s back", h.running, base)
	}
	if !layers.HarnessFailed(target) {
		t.Fatal("the failed package was not recorded")
	}
	reloads := l.mgr.(*fakeReloader).reloads
	l.recheck()
	if l.mgr.(*fakeReloader).reloads != reloads {
		t.Fatal("a package that failed was tried again")
	}
}

func sealedFixture(t *testing.T) (*layeredRuntime, *[]string, string, string, []byte) {
	t.Helper()
	env := newLayeredEnv(t)
	program := []byte("sealed v2")
	target := env.serve(program)
	asked := &[]string{}
	requestSealedSwitch = func(h string) error { *asked = append(*asked, h); return nil }
	own := strings.Repeat("aa", 32)
	h := &fakeHarness{}
	l := &layeredRuntime{sealedHash: own,
		lists:   fakeLists{sealed: map[string]bool{own: true, target: true}, latestSealed: target},
		harness: h, mgr: &fakeReloader{h: h}, ready: fakeReady{h: h}, picks: picksOf(settings.Versions{})}
	return l, asked, own, target, program
}

func TestRecheckHandsOverToThePickedSealed(t *testing.T) {
	l, asked, _, target, program := sealedFixture(t)
	l.picks = picksOf(settings.Versions{Sealed: "0x" + target})
	l.recheck()
	if len(*asked) != 1 || (*asked)[0] != target || !l.handedOver.Load() {
		t.Fatalf("asked %v, handed over %v", *asked, l.handedOver.Load())
	}
	if b, err := os.ReadFile(layers.StagedSealedPath(target)); err != nil || !bytes.Equal(b, program) {
		t.Fatalf("staged %q, %v", b, err)
	}
	l.recheck()
	if len(*asked) != 1 {
		t.Fatal("asked again after handing over")
	}
}

func TestRecheckMovesOffADelistedSealed(t *testing.T) {
	l, asked, own, target, _ := sealedFixture(t)
	l.recheck()
	if len(*asked) != 0 {
		t.Fatalf("switched while its own version is listed: %v", *asked)
	}
	lists := l.lists.(fakeLists)
	delete(lists.sealed, own)
	l.lists = lists
	l.recheck()
	if len(*asked) != 1 || (*asked)[0] != target {
		t.Fatalf("asked %v, want the newest listed %s", *asked, target)
	}
}

func TestSwitchSealedSkips(t *testing.T) {
	env := newLayeredEnv(t)
	target := env.serve([]byte("sealed v2"))
	requestSealedSwitch = func(string) error { t.Fatal("asked to switch"); return nil }
	own := strings.Repeat("aa", 32)

	l := &layeredRuntime{sealedHash: own, lists: fakeLists{sealed: map[string]bool{}}}
	if l.switchSealed(context.Background(), target) {
		t.Fatal("switched to an unlisted version")
	}
	l.lists = fakeLists{sealed: map[string]bool{target: true}}
	if l.switchSealed(context.Background(), own) {
		t.Fatal("switched to itself")
	}
	if err := os.MkdirAll(layers.LoaderDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layers.LoaderDir, "failed"), []byte(target+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l.switchSealed(context.Background(), target) {
		t.Fatal("switched to a version the loader went back from")
	}
}

// A package the list explicitly does not hold never starts, not even base's
// or the one this container ran last.
func TestChooseHarnessNeverStartsAnUnlistedOne(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{}}}
	if hash, _, err := l.chooseHarness(context.Background(), "", base); !errors.Is(err, errNoListedHarness) || isTransient(err) {
		t.Fatalf("chose %q (%v), want errNoListedHarness", hash, err)
	}
}

// The list cannot be read for the pick, and says base is not listed: nothing
// starts now, and the error is transient (the boot is tried again later).
func TestChooseHarnessDoesNotFallBackToADelistedBase(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	pick := env.serve(testPackage(t, "pick"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{}, unreadableFor: map[string]bool{pick: true}}}
	if hash, _, err := l.chooseHarness(context.Background(), "0x"+pick, base); err == nil || !isTransient(err) {
		t.Fatalf("chose %q (%v), want a transient error", hash, err)
	}
}

// Listed packages that do not install are tried again, then the error is
// transient; a delisted base is not started meanwhile.
func TestChooseHarnessRetriesInstallsThenGivesUp(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	missing := hexSum([]byte("not served"))
	old := harnessInstallBackoff
	harnessInstallBackoff = time.Millisecond
	t.Cleanup(func() { harnessInstallBackoff = old })
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{missing: true}, latestHarness: missing}}
	if hash, _, err := l.chooseHarness(context.Background(), "", base); err == nil || !isTransient(err) {
		t.Fatalf("chose %q (%v), want a transient error", hash, err)
	}
}

// startFirst: a package chosen at boot that does not start is recorded as
// failed and the next one starts; the choice is recorded once up.
func TestStartFirstFallsBackWhenThePackageDoesNotStart(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	target := env.serve(testPackage(t, "target"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{base: true, target: true}, latestHarness: target}}
	hash, dir, err := l.chooseHarness(context.Background(), "", base)
	if err != nil || hash != target {
		t.Fatalf("chose %s (%v)", hash, err)
	}
	h := &fakeHarness{}
	h.UseHarness(hash, dir)
	starts, stops := 0, 0
	start := func() error {
		starts++
		if h.next == target {
			return fmt.Errorf("harness.Start: %w: exited", framework.ErrHarnessDidNotStart)
		}
		h.running = h.next
		return nil
	}
	if err := l.startFirst(context.Background(), h, start, func(context.Context) { stops++ }); err != nil {
		t.Fatal(err)
	}
	if h.running != base || starts != 2 || stops != 1 {
		t.Fatalf("running %s after %d starts, %d stops", h.running, starts, stops)
	}
	if !layers.HarnessFailed(target) {
		t.Fatal("the package that did not start was not recorded")
	}
	if got := layers.LoadHarnessSelection(); got.Current != base {
		t.Fatalf("selection %+v, want base once it came up", got)
	}
}

// Base's package failing fails the start; another kind of failure (the
// settings, the key) is not the package's, and nothing is recorded.
func TestStartFirstFailsWhenBaseOrSomethingElseFails(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{base: true}, latestHarness: base}}
	if hash, _, err := l.chooseHarness(context.Background(), "", base); err != nil || hash != base {
		t.Fatalf("chose %s (%v)", hash, err)
	}
	h := &fakeHarness{}
	didNotStart := fmt.Errorf("%w: exited", framework.ErrHarnessDidNotStart)
	if err := l.startFirst(context.Background(), h, func() error { return didNotStart }, func(context.Context) {}); !errors.Is(err, didNotStart) {
		t.Fatalf("err %v", err)
	}
	if layers.HarnessFailed(base) {
		t.Fatal("base recorded as failed")
	}

	target := env.serve(testPackage(t, "target"))
	l = &layeredRuntime{lists: fakeLists{harness: map[string]bool{base: true, target: true}, latestHarness: target}}
	if hash, _, err := l.chooseHarness(context.Background(), "", base); err != nil || hash != target {
		t.Fatalf("chose %s (%v)", hash, err)
	}
	other := errors.New("no inference key")
	if err := l.startFirst(context.Background(), h, func() error { return other }, func(context.Context) {}); !errors.Is(err, other) {
		t.Fatalf("err %v", err)
	}
	if layers.HarnessFailed(target) {
		t.Fatal("a package recorded as failed for a failure that is not its own")
	}
}

// A harness restart that did not happen (the agent stopping) records
// nothing against the package.
func TestSwitchHarnessNotRestartedRecordsNothing(t *testing.T) {
	l, h, base, target := switchFixture(t, false)
	l.mgr = stoppedReloader{}
	l.picks = picksOf(settings.Versions{Harness: "0x" + target})
	l.recheck()
	if layers.HarnessFailed(target) {
		t.Fatal("a package recorded as failed because the agent was stopping")
	}
	if h.next != base {
		t.Fatalf("next %s, want base %s back", h.next, base)
	}
}

type stoppedReloader struct{}

func (stoppedReloader) Reload(context.Context) error { return manager.ErrStopped }

// The image's own sealed, run in place of another version, applies the rule
// as that version would, and goes back to it once the list confirms it.
func TestSealedTargetInPlaceOfAnother(t *testing.T) {
	newLayeredEnv(t)
	own, other, pick, newest := strings.Repeat("aa", 32), strings.Repeat("bb", 32), strings.Repeat("cc", 32), strings.Repeat("dd", 32)
	l := &layeredRuntime{sealedHash: own, insteadOf: other,
		lists: fakeLists{sealed: map[string]bool{own: true, other: true, pick: true, newest: true}, latestSealed: newest}}
	if got, ok := l.sealedTarget(context.Background(), ""); !ok || got != other {
		t.Fatalf("target %q %v, want back to %s", got, ok, other)
	}
	if got, ok := l.sealedTarget(context.Background(), "0x"+pick); !ok || got != pick {
		t.Fatalf("target %q %v, want the pick %s", got, ok, pick)
	}
	// The one stood in for is delisted: the newest listed, as it would move.
	l.lists = fakeLists{sealed: map[string]bool{own: true, newest: true}, latestSealed: newest}
	if got, ok := l.sealedTarget(context.Background(), ""); !ok || got != newest {
		t.Fatalf("target %q %v, want the newest listed %s", got, ok, newest)
	}
	// Still unreadable: stay.
	l.lists = fakeLists{unreadable: true}
	if got, ok := l.sealedTarget(context.Background(), ""); ok {
		t.Fatalf("target %q while the list is unreadable", got)
	}
}

// A switch to a version staged already takes it from the loader's directory,
// without a download.
func TestSwitchSealedUsesTheStagedProgram(t *testing.T) {
	newLayeredEnv(t)
	program := []byte("sealed v2")
	target := hexSum(program)
	if err := os.MkdirAll(filepath.Join(layers.LoaderDir, "sealed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layers.StagedSealedPath(target), program, 0o500); err != nil {
		t.Fatal(err)
	}
	asked := ""
	requestSealedSwitch = func(h string) error { asked = h; return nil }
	l := &layeredRuntime{sealedHash: strings.Repeat("aa", 32), lists: fakeLists{sealed: map[string]bool{target: true}}}
	if !l.switchSealed(context.Background(), target) || asked != target {
		t.Fatalf("asked %q", asked)
	}
}

// A switch request the loader does not act on lapses: the sealed carries on.
func TestHandOverLapses(t *testing.T) {
	env := newLayeredEnv(t)
	target := env.serve([]byte("sealed v2"))
	requestSealedSwitch = func(string) error { return nil }
	old := handOverTimeout
	handOverTimeout = 50 * time.Millisecond
	t.Cleanup(func() { handOverTimeout = old })
	l := &layeredRuntime{sealedHash: strings.Repeat("aa", 32), lists: fakeLists{sealed: map[string]bool{target: true}}}
	if !l.switchSealed(context.Background(), target) || !l.handedOver.Load() {
		t.Fatal("did not hand over")
	}
	start := time.Now()
	l.awaitHandOver()
	if l.handedOver.Load() || time.Since(start) > 5*time.Second {
		t.Fatalf("handed over %v after %v", l.handedOver.Load(), time.Since(start))
	}
}

// An artifact that did not hash to its name is not downloaded again in this
// container.
func TestArtifactMismatchIsRemembered(t *testing.T) {
	env := newLayeredEnv(t)
	name := hexSum([]byte("the real package"))
	env.artifacts[name] = []byte("something else")
	l := &layeredRuntime{}
	if err := l.installHarness(context.Background(), name); !errors.Is(err, layers.ErrHashMismatch) {
		t.Fatalf("install: %v, want a hash mismatch", err)
	}
	delete(env.artifacts, name) // a second download would now 404
	if err := l.installHarness(context.Background(), name); !errors.Is(err, layers.ErrHashMismatch) {
		t.Fatalf("second install: %v, want the remembered mismatch", err)
	}
}

// Pruning keeps base's package, the running one, the selection and the
// owner's pick, the staged sealed versions the loader names and this one; it
// removes the rest, and what a cut-off install left.
func TestPruneRemovesWhatNothingRuns(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	keep, old := testPackage(t, "keep"), testPackage(t, "old")
	for _, p := range [][]byte{keep, old} {
		if err := layers.InstallHarness(layers.VerifyingReader(nopCloser{bytes.NewReader(p)}, hexSum(p)), hexSum(p)); err != nil {
			t.Fatal(err)
		}
	}
	stale := filepath.Join(layers.PackagesDir, ".install-x")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	own, current, gone := strings.Repeat("aa", 32), strings.Repeat("bb", 32), strings.Repeat("cc", 32)
	if err := os.MkdirAll(filepath.Join(layers.LoaderDir, "sealed"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{own, current, gone} {
		if err := os.WriteFile(layers.StagedSealedPath(h), []byte(h), 0o500); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(layers.LoaderDir, "current"), []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &fakeHarness{running: base}
	l := &layeredRuntime{sealedHash: own, harness: h, picks: picksOf(settings.Versions{Harness: "0x" + hexSum(keep)})}
	l.prune()
	for _, p := range []string{base, hexSum(keep)} {
		if !layers.HarnessInstalled(p) {
			t.Fatalf("package %s removed", p)
		}
	}
	if layers.HarnessInstalled(hexSum(old)) {
		t.Fatal("an old package kept")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("a cut-off install kept")
	}
	for h, want := range map[string]bool{own: true, current: true, gone: false} {
		if _, err := os.Stat(layers.StagedSealedPath(h)); (err == nil) != want {
			t.Fatalf("staged %s present=%v, want %v", h, err == nil, want)
		}
	}
}

// failTrial: a cause outside the version is TrialTransientExit, any other
// TrialFailedExit; a sealed not on trial does not exit.
func TestFailTrialExitCodes(t *testing.T) {
	old := exitSealedProcess
	t.Cleanup(func() { exitSealedProcess = old })
	var codes []int
	exitSealedProcess = func(code int) { codes = append(codes, code) }
	trial := &config.Bootstrap{Trial: true}
	failTrial(trial, "chain bootstrap", transient(errors.New("rpc down")))
	failTrial(trial, "framework resolve", errors.New("no such framework"))
	failTrial(&config.Bootstrap{}, "agent start", errors.New("x"))
	if want := []int{layers.TrialTransientExit, layers.TrialFailedExit}; !reflect.DeepEqual(codes, want) {
		t.Fatalf("exit codes %v, want %v", codes, want)
	}
}
