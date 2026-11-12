package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/layers"
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
// kind's newest listed hash.
type fakeLists struct {
	sealed, harness             map[string]bool
	latestSealed, latestHarness string
	unreadable                  bool
}

func (f fakeLists) Listed(_ context.Context, kind, h [32]byte) (bool, error) {
	if f.unreadable {
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

	hash, dir := l.chooseHarness(context.Background(), "0x"+target, base)
	if hash != target || dir != layers.HarnessDir(target) || !layers.HarnessInstalled(target) {
		t.Fatalf("chose %s at %s", hash, dir)
	}
	if got := layers.LoadHarnessSelection(); got.Current != target {
		t.Fatalf("selection %+v", got)
	}
}

func TestChooseHarnessSkipsWhatIsNotListed(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	target := env.serve(testPackage(t, "target"))
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{base: true}}}

	if hash, _ := l.chooseHarness(context.Background(), "0x"+target, base); hash != base {
		t.Fatalf("chose %s, want base %s", hash, base)
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
	if hash, _ := l.chooseHarness(context.Background(), "", base); hash != newest {
		t.Fatalf("chose %s, want the newest listed %s", hash, newest)
	}
}

// Without a chain to confirm anything, the package this container has runs.
func TestChooseHarnessUnconfirmedRunsWhatIsInstalled(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	l := &layeredRuntime{}
	if hash, _ := l.chooseHarness(context.Background(), "0x"+env.serve(testPackage(t, "target")), base); hash != base {
		t.Fatalf("chose %s, want base %s", hash, base)
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
	if len(*asked) != 1 || (*asked)[0] != target || !l.handedOver {
		t.Fatalf("asked %v, handed over %v", *asked, l.handedOver)
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
