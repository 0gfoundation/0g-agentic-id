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
// from a fake attestor.
type layeredEnv struct {
	url       string
	artifacts map[string][]byte
}

func newLayeredEnv(t *testing.T) *layeredEnv {
	t.Helper()
	oldP, oldL, oldS, oldReq := layers.PackagesDir, layers.LoaderDir, framework.StateDir, requestSealedSwitch
	layers.PackagesDir = filepath.Join(t.TempDir(), "0g-harness")
	layers.LoaderDir = filepath.Join(t.TempDir(), "loader")
	framework.StateDir = t.TempDir()
	t.Cleanup(func() {
		layers.PackagesDir, layers.LoaderDir, framework.StateDir, requestSealedSwitch = oldP, oldL, oldS, oldReq
	})
	env := &layeredEnv{artifacts: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := env.artifacts[strings.TrimPrefix(r.URL.Path, "/artifacts/0x")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	env.url = srv.URL
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

// fakeAllow lists what it holds.
type fakeAllow struct{ sealed, harness map[string]bool }

func (f fakeAllow) IsValidSealedHash(_ context.Context, h [32]byte) (bool, error) {
	return f.sealed[hex.EncodeToString(h[:])], nil
}

func (f fakeAllow) IsValidHarnessHash(_ context.Context, h [32]byte) (bool, error) {
	return f.harness[hex.EncodeToString(h[:])], nil
}

func TestChooseHarnessTakesTheListedTarget(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	target := env.serve(testPackage(t, "target"))
	l := &layeredRuntime{attestorURL: env.url, allow: fakeAllow{harness: map[string]bool{base: true, target: true}}}

	hash, dir := l.chooseHarness(context.Background(), target, base)
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
	l := &layeredRuntime{attestorURL: env.url, allow: fakeAllow{harness: map[string]bool{base: true}}}

	if hash, _ := l.chooseHarness(context.Background(), target, base); hash != base {
		t.Fatalf("chose %s, want base %s", hash, base)
	}
	if layers.HarnessInstalled(target) {
		t.Fatal("an unlisted target was installed")
	}
}

// Without a chain to confirm anything, the package this container has runs.
func TestChooseHarnessUnconfirmedRunsWhatIsInstalled(t *testing.T) {
	env := newLayeredEnv(t)
	base := env.installBase(t, testPackage(t, "base"))
	l := &layeredRuntime{attestorURL: env.url}
	if hash, _ := l.chooseHarness(context.Background(), env.serve(testPackage(t, "target")), base); hash != base {
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
	l := &layeredRuntime{attestorURL: env.url, allow: fakeAllow{harness: map[string]bool{base: true, target: true}},
		harness: h, mgr: &fakeReloader{h: h}, ready: ready}
	return l, h, base, target
}

func TestApplySwitchesTheHarness(t *testing.T) {
	l, h, base, target := switchFixture(t, false)
	l.apply(layers.Targets{Harness: "0x" + target})
	if h.running != target {
		t.Fatalf("running %s, want %s", h.running, target)
	}
	if got := layers.LoadHarnessSelection(); got.Current != target || got.Previous != base {
		t.Fatalf("selection %+v", got)
	}
}

func TestApplyGoesBackWhenTheHarnessDoesNotComeUp(t *testing.T) {
	l, h, base, target := switchFixture(t, true)
	l.apply(layers.Targets{Harness: "0x" + target})
	if h.running != base {
		t.Fatalf("running %s, want base %s back", h.running, base)
	}
	if !layers.HarnessFailed(target) {
		t.Fatal("the failed package was not recorded")
	}
	reloads := l.mgr.(*fakeReloader).reloads
	l.apply(layers.Targets{Harness: "0x" + target})
	if l.mgr.(*fakeReloader).reloads != reloads {
		t.Fatal("a package that failed was tried again")
	}
}

func TestApplyHandsOverToANewSealed(t *testing.T) {
	env := newLayeredEnv(t)
	program := []byte("sealed v2")
	target := env.serve(program)
	var asked []string
	requestSealedSwitch = func(h string) error { asked = append(asked, h); return nil }
	h := &fakeHarness{}
	l := &layeredRuntime{attestorURL: env.url, sealedHash: strings.Repeat("aa", 32),
		allow: fakeAllow{sealed: map[string]bool{target: true}}, harness: h, mgr: &fakeReloader{h: h}, ready: fakeReady{h: h}}

	l.apply(layers.Targets{Sealed: "0x" + target})
	if len(asked) != 1 || asked[0] != target || !l.handedOver {
		t.Fatalf("asked %v, handed over %v", asked, l.handedOver)
	}
	if b, err := os.ReadFile(layers.StagedSealedPath(target)); err != nil || !bytes.Equal(b, program) {
		t.Fatalf("staged %q, %v", b, err)
	}
	l.apply(layers.Targets{Sealed: "0x" + target})
	if len(asked) != 1 {
		t.Fatal("asked again after handing over")
	}
}

func TestSwitchSealedSkips(t *testing.T) {
	env := newLayeredEnv(t)
	target := env.serve([]byte("sealed v2"))
	requestSealedSwitch = func(string) error { t.Fatal("asked to switch"); return nil }
	own := strings.Repeat("aa", 32)

	l := &layeredRuntime{attestorURL: env.url, sealedHash: own, allow: fakeAllow{sealed: map[string]bool{}}}
	if l.switchSealed(context.Background(), target) {
		t.Fatal("switched to an unlisted version")
	}
	l.allow = fakeAllow{sealed: map[string]bool{target: true}}
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
