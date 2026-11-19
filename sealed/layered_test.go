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
	"slices"
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

// install installs a package, as an earlier boot in this container would
// have.
func (e *layeredEnv) install(t *testing.T, pkg []byte) string {
	t.Helper()
	h := hexSum(pkg)
	if err := layers.InstallHarness(layers.VerifyingReader(nopCloser{bytes.NewReader(pkg)}, h), h); err != nil {
		t.Fatal(err)
	}
	return h
}

// ranLast records package h as the one this container ran last.
func ranLast(t *testing.T, h string) {
	t.Helper()
	if err := layers.SaveHarnessSelection(layers.HarnessSelection{Current: h}); err != nil {
		t.Fatal(err)
	}
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// fakeLists is a trust registry: each kind's listed hashes, oldest first,
// so the last is the newest. unreadable fails every read.
type fakeLists struct {
	sealed, harness []string
	unreadable      bool
}

func (f fakeLists) of(kind [32]byte) []string {
	if kind == kindSealed {
		return f.sealed
	}
	return f.harness
}

func (f fakeLists) Listed(_ context.Context, kind, h [32]byte) (bool, error) {
	if f.unreadable {
		return false, errors.New("rpc down")
	}
	return slices.Contains(f.of(kind), hex.EncodeToString(h[:])), nil
}

func (f fakeLists) Latest(_ context.Context, kind [32]byte) ([32]byte, error) {
	if f.unreadable {
		return [32]byte{}, errors.New("rpc down")
	}
	listed := f.of(kind)
	if len(listed) == 0 {
		return [32]byte{}, nil
	}
	return layers.Bytes32(listed[len(listed)-1]), nil
}

func (f fakeLists) Versions(_ context.Context, kind [32]byte) ([][32]byte, error) {
	if f.unreadable {
		return nil, errors.New("rpc down")
	}
	var out [][32]byte
	for _, h := range f.of(kind) {
		out = append(out, layers.Bytes32(h))
	}
	return out, nil
}

func picksOf(v settings.Versions) func() settings.Versions {
	return func() settings.Versions { return v }
}

// The owner's pick, while listed, comes before the newest listed package.
func TestChooseHarnessTakesTheListedPick(t *testing.T) {
	env := newLayeredEnv(t)
	target := env.serve(testPackage(t, "target"))
	newest := env.serve(testPackage(t, "newest"))
	l := &layeredRuntime{lists: fakeLists{harness: []string{target, newest}}}

	hash, dir, err := l.chooseHarness(context.Background(), "0x"+target)
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
	listed := env.serve(testPackage(t, "listed"))
	target := env.serve(testPackage(t, "target"))
	l := &layeredRuntime{lists: fakeLists{harness: []string{listed}}}

	if hash, _, err := l.chooseHarness(context.Background(), "0x"+target); hash != listed || err != nil {
		t.Fatalf("chose %s (%v), want the listed %s", hash, err, listed)
	}
	if layers.HarnessInstalled(target) {
		t.Fatal("an unlisted pick was installed")
	}
}

// A fresh container with no pick downloads the newest listed package.
func TestChooseHarnessFreshContainerTakesTheNewestListed(t *testing.T) {
	env := newLayeredEnv(t)
	older := env.serve(testPackage(t, "older"))
	newest := env.serve(testPackage(t, "newest"))
	l := &layeredRuntime{lists: fakeLists{harness: []string{older, newest}}}
	if hash, _, err := l.chooseHarness(context.Background(), ""); hash != newest || err != nil || !layers.HarnessInstalled(newest) {
		t.Fatalf("chose %s (%v), want the newest listed %s", hash, err, newest)
	}
}

// The package this container ran last stays while listed, though a newer one
// is listed; one that failed here gives way to the next newest listed one.
func TestChooseHarnessKeepsTheOneThisContainerRan(t *testing.T) {
	env := newLayeredEnv(t)
	older := env.install(t, testPackage(t, "older"))
	middle := env.serve(testPackage(t, "middle"))
	newest := env.serve(testPackage(t, "newest"))
	ranLast(t, older)
	l := &layeredRuntime{lists: fakeLists{harness: []string{older, middle, newest}}}
	if hash, _, err := l.chooseHarness(context.Background(), ""); hash != older || err != nil {
		t.Fatalf("chose %s (%v), want the one it ran, %s", hash, err, older)
	}
	layers.MarkHarnessFailed(older)
	layers.MarkHarnessFailed(newest)
	if hash, _, err := l.chooseHarness(context.Background(), ""); hash != middle || err != nil {
		t.Fatalf("chose %s (%v), want the newest listed one that did not fail, %s", hash, err, middle)
	}
}

// When the list cannot be read, only the package this container ran last
// starts, and only when it is here and did not fail; else the boot is tried
// again later (transient). No chain client reads the same.
func TestChooseHarnessUnreadableListRunsOnlyWhatThisContainerRan(t *testing.T) {
	env := newLayeredEnv(t)
	pick := env.serve(testPackage(t, "pick"))
	for _, l := range []*layeredRuntime{{lists: fakeLists{unreadable: true}}, {}} {
		if hash, _, err := l.chooseHarness(context.Background(), "0x"+pick); err == nil || !isTransient(err) {
			t.Fatalf("fresh container: chose %q (%v), want a transient error", hash, err)
		}
	}
	if layers.HarnessInstalled(pick) {
		t.Fatal("an unconfirmed pick was installed")
	}
	ran := env.install(t, testPackage(t, "ran"))
	ranLast(t, ran)
	l := &layeredRuntime{lists: fakeLists{unreadable: true}}
	if hash, _, err := l.chooseHarness(context.Background(), "0x"+pick); hash != ran || err != nil {
		t.Fatalf("chose %s (%v), want the one this container ran, %s", hash, err, ran)
	}
	layers.MarkHarnessFailed(ran)
	if hash, _, err := l.chooseHarness(context.Background(), ""); err == nil || !isTransient(err) {
		t.Fatalf("chose %q (%v) after it failed, want a transient error", hash, err)
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

// switchFixture runs package first, with target served and both listed,
// target the newer.
func switchFixture(t *testing.T, bad bool) (*layeredRuntime, *fakeHarness, string, string) {
	t.Helper()
	env := newLayeredEnv(t)
	first := env.install(t, testPackage(t, "first"))
	target := env.serve(testPackage(t, "target"))
	h := &fakeHarness{next: first, running: first}
	ready := fakeReady{h: h}
	if bad {
		ready.bad = target
	}
	old := harnessReadyTimeout
	harnessReadyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { harnessReadyTimeout = old })
	own := strings.Repeat("aa", 32)
	l := &layeredRuntime{sealedHash: own,
		lists:   fakeLists{sealed: []string{own}, harness: []string{first, target}},
		harness: h, mgr: &fakeReloader{h: h}, ready: ready, picks: picksOf(settings.Versions{})}
	return l, h, first, target
}

func TestRecheckSwitchesTheHarnessToThePick(t *testing.T) {
	l, h, first, target := switchFixture(t, false)
	l.picks = picksOf(settings.Versions{Harness: "0x" + target})
	l.recheck()
	if h.running != target {
		t.Fatalf("running %s, want %s", h.running, target)
	}
	if got := layers.LoadHarnessSelection(); got.Current != target || got.Previous != first {
		t.Fatalf("selection %+v", got)
	}
}

// No pick, the running package still listed: a newer listed one does not
// move it (only a delisting does).
func TestRecheckStaysWhileTheRunningVersionIsListed(t *testing.T) {
	l, h, first, _ := switchFixture(t, false)
	l.recheck()
	if h.running != first || l.mgr.(*fakeReloader).reloads != 0 {
		t.Fatalf("running %s after %d reloads, want %s untouched", h.running, l.mgr.(*fakeReloader).reloads, first)
	}
}

func TestRecheckMovesOffADelistedHarness(t *testing.T) {
	l, h, _, target := switchFixture(t, false)
	lists := l.lists.(fakeLists)
	lists.harness = []string{target}
	l.lists = lists
	l.recheck()
	if h.running != target {
		t.Fatalf("running %s, want the newest listed %s", h.running, target)
	}
}

// A pick the registry does not list is not switched to.
func TestRecheckIgnoresAnUnlistedPick(t *testing.T) {
	l, h, first, _ := switchFixture(t, false)
	l.picks = picksOf(settings.Versions{Harness: "0x" + strings.Repeat("cd", 32)})
	l.recheck()
	if h.running != first {
		t.Fatalf("running %s, want %s", h.running, first)
	}
}

// A list that cannot be read keeps what runs.
func TestRecheckKeepsWhatRunsWhenTheListIsUnreadable(t *testing.T) {
	l, h, first, _ := switchFixture(t, false)
	l.lists = fakeLists{unreadable: true}
	l.recheck()
	if h.running != first {
		t.Fatalf("running %s, want %s", h.running, first)
	}
}

func TestRecheckGoesBackWhenTheHarnessDoesNotComeUp(t *testing.T) {
	l, h, first, target := switchFixture(t, true)
	l.picks = picksOf(settings.Versions{Harness: "0x" + target})
	l.recheck()
	if h.running != first {
		t.Fatalf("running %s, want %s back", h.running, first)
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
		lists:   fakeLists{sealed: []string{own, target}},
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
	lists.sealed = slices.DeleteFunc(slices.Clone(lists.sealed), func(h string) bool { return h == own })
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

	l := &layeredRuntime{sealedHash: own, lists: fakeLists{}}
	if l.switchSealed(context.Background(), target) {
		t.Fatal("switched to an unlisted version")
	}
	l.lists = fakeLists{sealed: []string{target}}
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

// A package the list does not hold never starts, not even the one this
// container ran last; with nothing listed (a fresh container before the
// first listing) the boot is retried later (transient), so a version listed
// afterwards is picked up.
func TestChooseHarnessNeverStartsAnUnlistedOne(t *testing.T) {
	env := newLayeredEnv(t)
	l := &layeredRuntime{lists: fakeLists{}}
	if hash, _, err := l.chooseHarness(context.Background(), ""); !errors.Is(err, errNoListedHarness) || !isTransient(err) {
		t.Fatalf("fresh container: chose %q (%v), want a transient errNoListedHarness", hash, err)
	}
	ranLast(t, env.install(t, testPackage(t, "delisted")))
	if hash, _, err := l.chooseHarness(context.Background(), ""); !errors.Is(err, errNoListedHarness) || !isTransient(err) {
		t.Fatalf("chose %q (%v), want a transient errNoListedHarness", hash, err)
	}
}

// Listed packages that do not install are tried again, then the error is
// transient; a delisted package this container has is not started meanwhile.
func TestChooseHarnessRetriesInstallsThenGivesUp(t *testing.T) {
	env := newLayeredEnv(t)
	ranLast(t, env.install(t, testPackage(t, "delisted")))
	missing := hexSum([]byte("not served"))
	old := harnessInstallBackoff
	harnessInstallBackoff = time.Millisecond
	t.Cleanup(func() { harnessInstallBackoff = old })
	l := &layeredRuntime{lists: fakeLists{harness: []string{missing}}}
	if hash, _, err := l.chooseHarness(context.Background(), ""); err == nil || !isTransient(err) {
		t.Fatalf("chose %q (%v), want a transient error", hash, err)
	}
}

// startFirst: a package chosen at boot that does not start is recorded as
// failed and the next one starts; the choice is recorded once up.
func TestStartFirstFallsBackWhenThePackageDoesNotStart(t *testing.T) {
	env := newLayeredEnv(t)
	older := env.serve(testPackage(t, "older"))
	target := env.serve(testPackage(t, "target"))
	l := &layeredRuntime{lists: fakeLists{harness: []string{older, target}}}
	hash, dir, err := l.chooseHarness(context.Background(), "")
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
	if h.running != older || starts != 2 || stops != 1 {
		t.Fatalf("running %s after %d starts, %d stops", h.running, starts, stops)
	}
	if !layers.HarnessFailed(target) {
		t.Fatal("the package that did not start was not recorded")
	}
	if got := layers.LoadHarnessSelection(); got.Current != older {
		t.Fatalf("selection %+v, want %s once it came up", got, older)
	}
}

// When no other package can start, the start fails, transient: a package
// listed later is picked up. Another kind of failure (the settings, the key)
// is not the package's, and nothing is recorded.
func TestStartFirstFailsWhenNothingElseStartsOrSomethingElseFails(t *testing.T) {
	env := newLayeredEnv(t)
	only := env.serve(testPackage(t, "only"))
	l := &layeredRuntime{lists: fakeLists{harness: []string{only}}}
	if hash, _, err := l.chooseHarness(context.Background(), ""); err != nil || hash != only {
		t.Fatalf("chose %s (%v)", hash, err)
	}
	h := &fakeHarness{}
	didNotStart := fmt.Errorf("%w: exited", framework.ErrHarnessDidNotStart)
	err := l.startFirst(context.Background(), h, func() error { return didNotStart }, func(context.Context) {})
	if !errors.Is(err, didNotStart) || !errors.Is(err, errNoListedHarness) || !isTransient(err) {
		t.Fatalf("err %v, want the start's and a transient errNoListedHarness", err)
	}
	if !layers.HarnessFailed(only) {
		t.Fatal("the package that did not start was not recorded")
	}

	target := env.serve(testPackage(t, "target"))
	l = &layeredRuntime{lists: fakeLists{harness: []string{only, target}}}
	if hash, _, err := l.chooseHarness(context.Background(), ""); err != nil || hash != target {
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
	l, h, first, target := switchFixture(t, false)
	l.mgr = stoppedReloader{}
	l.picks = picksOf(settings.Versions{Harness: "0x" + target})
	l.recheck()
	if layers.HarnessFailed(target) {
		t.Fatal("a package recorded as failed because the agent was stopping")
	}
	if h.next != first {
		t.Fatalf("next %s, want %s back", h.next, first)
	}
}

type stoppedReloader struct{}

func (stoppedReloader) Reload(context.Context) error { return manager.ErrStopped }

// The sealed layer's rule: the listed pick, else this version while it is
// listed, else the newest listed one; a list that cannot be read keeps this
// one.
func TestSealedTarget(t *testing.T) {
	newLayeredEnv(t)
	own, pick, newest := strings.Repeat("aa", 32), strings.Repeat("cc", 32), strings.Repeat("dd", 32)
	l := &layeredRuntime{sealedHash: own, lists: fakeLists{sealed: []string{own, pick, newest}}}
	if got, ok := l.sealedTarget(context.Background(), ""); ok {
		t.Fatalf("target %q while this version is listed", got)
	}
	if got, ok := l.sealedTarget(context.Background(), "0x"+pick); !ok || got != pick {
		t.Fatalf("target %q %v, want the pick %s", got, ok, pick)
	}
	l.lists = fakeLists{sealed: []string{pick, newest}}
	if got, ok := l.sealedTarget(context.Background(), ""); !ok || got != newest {
		t.Fatalf("target %q %v, want the newest listed %s", got, ok, newest)
	}
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
	l := &layeredRuntime{sealedHash: strings.Repeat("aa", 32), lists: fakeLists{sealed: []string{target}}}
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
	l := &layeredRuntime{sealedHash: strings.Repeat("aa", 32), lists: fakeLists{sealed: []string{target}}}
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

// Pruning keeps the running package, the selection's current and previous
// and the owner's pick, the staged sealed versions the loader names and this
// one; it removes the rest, and what a cut-off install left.
func TestPruneRemovesWhatNothingRuns(t *testing.T) {
	env := newLayeredEnv(t)
	running := env.install(t, testPackage(t, "running"))
	previous := env.install(t, testPackage(t, "previous"))
	keep, old := env.install(t, testPackage(t, "keep")), env.install(t, testPackage(t, "old"))
	if err := layers.SaveHarnessSelection(layers.HarnessSelection{Current: running, Previous: previous}); err != nil {
		t.Fatal(err)
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
	h := &fakeHarness{running: running}
	l := &layeredRuntime{sealedHash: own, harness: h, picks: picksOf(settings.Versions{Harness: "0x" + keep})}
	l.prune()
	for _, p := range []string{running, previous, keep} {
		if !layers.HarnessInstalled(p) {
			t.Fatalf("package %s removed", p)
		}
	}
	if layers.HarnessInstalled(old) {
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

// exitForRetry ends a sealed the loader started for the loader to start it
// again later; a sealed that is PID 1 itself stays.
func TestExitForRetry(t *testing.T) {
	old := exitSealedProcess
	t.Cleanup(func() { exitSealedProcess = old })
	var codes []int
	exitSealedProcess = func(code int) { codes = append(codes, code) }
	exitForRetry(&config.Bootstrap{}, "harness choice", errNoListedHarness)
	exitForRetry(&config.Bootstrap{SealedHash: strings.Repeat("aa", 32)}, "provisioning", errors.New("the attestor does not declare the layered flow"))
	if want := []int{layers.TrialTransientExit}; !reflect.DeepEqual(codes, want) {
		t.Fatalf("exit codes %v, want %v", codes, want)
	}
}
