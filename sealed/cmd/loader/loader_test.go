package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	helperEnv = "LOADER_TEST_HELPER"
	readyEnv  = "LOADER_TEST_READY"
	stateEnv  = "LOADER_TEST_STATE"
	// firstEnv is the hash of the version a switch test starts on; failEnv
	// names a version that fails its trial (exits 75 without confirming).
	firstEnv = "LOADER_TEST_FIRST"
	failEnv  = "LOADER_TEST_FAIL"
)

// TestMain doubles as the sealed the tests supervise: with LOADER_TEST_HELPER
// set, the test binary acts out the named mode instead of running tests.
// Every version a test serves or stages is a copy of this binary with bytes
// appended (so another hash) and runs the same modes; SEALED_HASH, set by the
// loader, tells it which version it is.
func TestMain(m *testing.M) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		os.Exit(m.Run())
	}
	state := os.Getenv(stateEnv)
	me := os.Getenv(sealedHashEnv)
	confirm := func() { _ = os.WriteFile(filepath.Join(state, "confirmed"), []byte(me), 0o600) }
	waitTerm := func(code int) {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		ready()
		<-c
		os.Exit(code)
	}
	runs := func() int {
		p := filepath.Join(state, "runs")
		n, _ := strconv.Atoi(readTrim(p))
		_ = os.WriteFile(p, []byte(strconv.Itoa(n+1)), 0o600)
		return n + 1
	}
	switch mode {
	case "report":
		// Notes which version ran and whether on trial, then fails its trial
		// when it is the one to fail, else confirms and waits to be stopped.
		f, _ := os.OpenFile(filepath.Join(state, "report"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		fmt.Fprintf(f, "%s %s\n", me, os.Getenv(trialEnv))
		f.Close()
		if me == os.Getenv(failEnv) {
			os.Exit(75)
		}
		confirm()
		waitTerm(0)
	case "term3":
		confirm()
		waitTerm(3)
	case "ignore-term":
		confirm()
		signal.Ignore(syscall.SIGTERM)
		ready()
		time.Sleep(time.Minute)
		os.Exit(0)
	case "switch", "switch-fail", "switch-transient", "switch-silent":
		helperSwitch(mode, me, confirm, waitTerm, runs)
	case "owner-restart":
		// Exits for an owner restart more often than a crash is allowed to,
		// then waits to be stopped.
		confirm()
		if runs() <= maxRestarts+2 {
			os.Exit(restartRequestedExit)
		}
		waitTerm(0)
	case "bad-request":
		confirm()
		_ = os.WriteFile(filepath.Join(state, "request"), []byte(strings.Repeat("ab", 32)), 0o600)
		_ = os.MkdirAll(filepath.Join(state, "sealed"), 0o700)
		_ = os.WriteFile(filepath.Join(state, "sealed", strings.Repeat("ab", 32)), []byte("not it"), 0o500)
		waitTerm(3)
	case "crash", "crash-loop":
		confirm()
		if n := runs(); mode == "crash" && n == 2 {
			waitTerm(0)
		}
		os.Exit(3)
	}
	os.Exit(2)
}

// helperSwitch: the first version stages a second one (this binary with
// "\nversion two\n" appended) and asks to switch, then waits to be stopped.
// The second version, in switch, confirms and waits to be stopped (exit 9);
// in switch-fail, exits 75 without confirming; in switch-transient, exits
// trialTransientExit on its first two starts (every start with
// LOADER_TEST_TRANSIENT_FOREVER), then confirms and waits to be stopped
// (exit 3); in switch-silent, never confirms or says it is ready, and exits
// 0 when stopped. Run
// again after the loader went back to it, the first version waits to be
// stopped and exits 4.
func helperSwitch(mode, me string, confirm func(), waitTerm func(int), runs func() int) {
	state := os.Getenv(stateEnv)
	if me != os.Getenv(firstEnv) {
		if os.Getenv(trialEnv) != "1" {
			os.Exit(8) // a version new here must start on trial
		}
		switch mode {
		case "switch-fail":
			os.Exit(75)
		case "switch-transient":
			if runs() <= 2 || os.Getenv("LOADER_TEST_TRANSIENT_FOREVER") != "" {
				os.Exit(trialTransientExit)
			}
			confirm()
			waitTerm(3)
		case "switch-silent":
			// Not even ready: only the trial limit stops it.
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGTERM)
			<-c
			os.Exit(0)
		}
		confirm()
		waitTerm(9)
	}
	if readTrim(filepath.Join(state, "failed")) != "" {
		waitTerm(4)
	}
	confirm()
	b, _ := os.ReadFile(os.Args[0])
	b = append(b, []byte("\nversion two\n")...)
	h := hashOf(b)
	_ = os.MkdirAll(filepath.Join(state, "sealed"), 0o700)
	_ = os.WriteFile(filepath.Join(state, "sealed", h), b, 0o500)
	_ = os.WriteFile(filepath.Join(state, "request"), []byte(h), 0o600)
	waitTerm(0)
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ready tells the test the helper has installed its signal handling.
func ready() {
	if p := os.Getenv(readyEnv); p != "" {
		_ = os.WriteFile(p, nil, 0o600)
	}
}

// fakeList is a sealed list that lists hashes (oldest first) and cannot be
// read for its next unreadable reads; refuseErr makes isListed unreadable.
type fakeList struct {
	mu         sync.Mutex
	hashes     []string
	unreadable int
	reads      int
	refuseErr  bool
}

var errUnreadable = errors.New("rpc down")

func (l *fakeList) listed() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads++
	if l.unreadable > 0 {
		l.unreadable--
		return nil, errUnreadable
	}
	return append([]string(nil), l.hashes...), nil
}

func (l *fakeList) refuses(h string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.refuseErr {
		return false, errUnreadable
	}
	for _, x := range l.hashes {
		if x == h {
			return false, nil
		}
	}
	return true, nil
}

func (l *fakeList) set(hashes ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hashes = hashes
}

func (l *fakeList) readCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reads
}

// artifacts serves bodies by name and counts the requests per name.
type artifacts struct {
	mu     sync.Mutex
	bodies map[string][]byte
	gets   map[string]int
	srv    *httptest.Server
}

func newArtifacts(t *testing.T) *artifacts {
	a := &artifacts{bodies: map[string][]byte{}, gets: map[string]int{}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		a.mu.Lock()
		a.gets[name]++
		body, ok := a.bodies[name]
		a.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *artifacts) serve(name string, body []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bodies[name] = body
}

func (a *artifacts) count(name string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gets[name]
}

// fixture is a supervisor over a fresh state directory, its list and the
// release it downloads from.
type fixture struct {
	s     *supervisor
	sigs  chan os.Signal
	ready string
	list  *fakeList
	art   *artifacts
	logs  *logRecorder
}

type logRecorder struct {
	mu    sync.Mutex
	t     *testing.T
	lines []string
}

func (r *logRecorder) logf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	r.mu.Lock()
	r.lines = append(r.lines, line)
	r.mu.Unlock()
	r.t.Log(line)
}

func (r *logRecorder) has(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func newFixture(t *testing.T, mode string, grace time.Duration) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "loader")
	readyFile := filepath.Join(t.TempDir(), "ready")
	// sealed inherits the loader's environment, so the helper mode travels
	// the same way.
	t.Setenv(helperEnv, mode)
	t.Setenv(readyEnv, readyFile)
	t.Setenv(stateEnv, dir)
	t.Setenv(sealedHashEnv, "")
	t.Setenv(trialEnv, "")
	t.Setenv(firstEnv, "")
	t.Setenv(failEnv, "")
	f := &fixture{sigs: make(chan os.Signal, 4), ready: readyFile, list: &fakeList{}, art: newArtifacts(t), logs: &logRecorder{t: t}}
	f.s = &supervisor{
		state:            stateDir(dir),
		allow:            f.list,
		artifacts:        f.art.srv.URL,
		http:             newArtifactClient(),
		stdout:           io.Discard,
		stderr:           io.Discard,
		sigs:             f.sigs,
		stopGrace:        grace,
		poll:             10 * time.Millisecond,
		backoff:          func(int) time.Duration { return 0 },
		window:           time.Minute,
		trialLimit:       time.Minute,
		transientLimit:   time.Hour,
		transientBackoff: func(int) time.Duration { return time.Millisecond },
		logf:             f.logs.logf,
	}
	if err := f.s.state.prepare(); err != nil {
		t.Fatal(err)
	}
	return f
}

// version makes a version of this binary with suffix appended, served on
// the release, and returns its hash and program.
func (f *fixture) version(t *testing.T, suffix string) (string, []byte) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, []byte(suffix)...)
	h := hashOf(b)
	f.art.serve(h, b)
	return h, b
}

// staged puts program b in the state directory under hash h, as a version
// this container ran before.
func (f *fixture) staged(t *testing.T, h string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(string(f.s.state), "sealed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.s.state.staged(h), b, 0o500); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) write(t *testing.T, name, content string) {
	t.Helper()
	if err := f.s.state.write(name, content); err != nil {
		t.Fatal(err)
	}
}

// report is the helper's lines "<hash> <trial>", one per run.
func (f *fixture) report() []string {
	b, _ := os.ReadFile(filepath.Join(string(f.s.state), "report"))
	r := strings.TrimSuffix(string(b), "\n")
	if r == "" {
		return nil
	}
	return strings.Split(r, "\n")
}

func runAsync(s *supervisor) <-chan int {
	done := make(chan int, 1)
	go func() { done <- s.run() }()
	return done
}

func waitReady(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p); err == nil {
			_ = os.Remove(p)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("helper never became ready")
}

func waitCode(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(30 * time.Second):
		t.Fatal("supervisor did not return")
		return 0
	}
}

// stopWhenReady stops the helper once it is ready and returns the loader's
// exit code.
func (f *fixture) stopWhenReady(t *testing.T, done <-chan int) int {
	t.Helper()
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGTERM
	return waitCode(t, done)
}

func TestVerifyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sealed")
	if err := os.WriteFile(p, []byte("sealed build"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := hashOf([]byte("sealed build"))

	if err := verifyFile(p, good); err != nil {
		t.Fatalf("matching hash refused: %v", err)
	}
	if err := verifyFile(p, strings.ToUpper(good)); err != nil {
		t.Fatalf("upper-case hex refused: %v", err)
	}
	for name, want := range map[string]string{
		"empty":    "",
		"mismatch": strings.Repeat("0", 64),
	} {
		if err := verifyFile(p, want); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
	if err := verifyFile(filepath.Join(t.TempDir(), "missing"), good); err == nil {
		t.Error("missing file: expected a refusal")
	}
}

// A fresh container downloads the newest listed version and runs it on
// trial; nothing else is downloaded.
func TestRunFetchesTheNewestListedVersionInAFreshContainer(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	a, _ := f.version(t, "\nA\n")
	b, _ := f.version(t, "\nB\n")
	f.list.set(a, b)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := f.report(); !reflect.DeepEqual(got, []string{b + " 1"}) {
		t.Fatalf("ran %q, want the newest on trial", got)
	}
	if f.s.state.hash("current") != b || f.s.state.read("confirmed") != b {
		t.Fatalf("current %q confirmed %q", f.s.state.hash("current"), f.s.state.read("confirmed"))
	}
	if f.art.count(b) != 1 || f.art.count(a) != 0 {
		t.Fatalf("downloads: newest %d, older %d", f.art.count(b), f.art.count(a))
	}
	if verifyFile(f.s.state.staged(b), b) != nil {
		t.Fatal("the download is not kept under its hash")
	}
	fi, err := os.Stat(f.s.state.staged(b))
	if err != nil || fi.Mode().Perm() != 0o500 {
		t.Fatalf("kept program mode %v (%v)", fi.Mode().Perm(), err)
	}
}

// The version this container ran last runs again while listed, though a
// newer one is listed: moving is the owner's pick or a delisting, not the
// loader's.
func TestRunKeepsTheVersionItRanWhileListed(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	a, ab := f.version(t, "\nA\n")
	b, _ := f.version(t, "\nB\n")
	f.staged(t, a, ab)
	f.write(t, "current", a)
	f.write(t, "confirmed", a)
	f.list.set(a, b)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := f.report(); !reflect.DeepEqual(got, []string{a + " "}) {
		t.Fatalf("ran %q, want the recorded version, not on trial", got)
	}
	if f.art.count(a)+f.art.count(b) != 0 {
		t.Fatal("downloaded what it had")
	}
}

// A delisted version does not run: the one it replaced runs while listed,
// else the newest listed one, downloaded.
func TestRunMovesOffADelistedVersion(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	a, ab := f.version(t, "\nA\n")
	b, bb := f.version(t, "\nB\n")
	c, _ := f.version(t, "\nC\n")
	f.staged(t, a, ab)
	f.staged(t, b, bb)
	f.write(t, "current", b)
	f.write(t, "previous", a)
	f.write(t, "confirmed", b)
	f.list.set(a)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if f.s.state.hash("current") != a || f.s.state.hash("previous") != "" {
		t.Fatalf("current %q previous %q, want the version it replaced", f.s.state.hash("current"), f.s.state.hash("previous"))
	}
	f.list.set(c)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := f.report(); !reflect.DeepEqual(got, []string{a + " 1", c + " 1"}) {
		t.Fatalf("ran %q, want the replaced version, then the newest listed", got)
	}
	if !f.logs.has("is not on the sealed list; not running it") {
		t.Fatal("no word of the delisted version")
	}
}

// While the list cannot be read nothing runs, the version this container ran
// last included; once it reads, the run goes on.
func TestRunRunsNothingWhileTheListCannotBeRead(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	a, ab := f.version(t, "\nA\n")
	f.staged(t, a, ab)
	f.write(t, "current", a)
	f.write(t, "confirmed", a)
	f.list.set(a)
	f.list.unreadable = 3
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := f.report(); !reflect.DeepEqual(got, []string{a + " "}) {
		t.Fatalf("ran %q, want one run once the list read", got)
	}
	if f.list.readCount() < 4 {
		t.Fatalf("read the list %d times", f.list.readCount())
	}
}

// A version the chain does not list never runs, however it got here; with
// nothing listed the loader waits, and a stop ends the wait.
func TestRunNeverRunsAVersionTheChainDoesNotList(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	x, xb := f.version(t, "\nX\n")
	f.staged(t, x, xb)
	f.write(t, "current", x)
	f.write(t, "confirmed", x)
	done := runAsync(f.s)
	for f.list.readCount() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	f.sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 128+int(syscall.SIGTERM) {
		t.Fatalf("exit code %d, want %d", code, 128+int(syscall.SIGTERM))
	}
	if got := f.report(); got != nil {
		t.Fatalf("ran %q", got)
	}
	if !f.logs.has("the sealed list is empty") {
		t.Fatal("no word of the empty list")
	}
}

// A download that does not hash to its name is not run, is remembered, and is
// not made again in this container; the loader takes the next listed version.
func TestRunRemembersADownloadThatDoesNotHashToItsName(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	a, _ := f.version(t, "\nA\n")
	b, _ := f.version(t, "\nB\n")
	f.art.serve(b, []byte("not B"))
	f.list.set(a, b)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := f.report(); !reflect.DeepEqual(got, []string{a + " 1"}) {
		t.Fatalf("ran %q, want the older listed version", got)
	}
	if !f.s.state.mismatched(b) {
		t.Fatal("the mismatch is not remembered")
	}
	if _, err := os.Stat(f.s.state.staged(b)); err == nil {
		t.Fatal("the bad download was kept")
	}
	f.write(t, "current", "")
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if f.art.count(b) != 1 {
		t.Fatalf("downloaded the mismatched version %d times", f.art.count(b))
	}
}

// A version that exits on trial before it confirms does not run here again:
// the loader takes the next listed one.
func TestRunTakesTheNextVersionWhenATrialFails(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	a, _ := f.version(t, "\nA\n")
	b, _ := f.version(t, "\nB\n")
	t.Setenv(failEnv, b)
	f.list.set(a, b)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := f.report(); !reflect.DeepEqual(got, []string{b + " 1", a + " 1"}) {
		t.Fatalf("ran %q, want the newest, then the next", got)
	}
	if !f.s.state.failed(b) || f.s.state.hash("current") != a {
		t.Fatalf("failed %v, current %q", f.s.state.failed(b), f.s.state.hash("current"))
	}
}

func TestRunForwardsStopSignal(t *testing.T) {
	f := newFixture(t, "term3", 5*time.Second)
	a, _ := f.version(t, "\nA\n")
	f.list.set(a)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 3 {
		t.Fatalf("exit code %d, want 3 (the helper's own exit on SIGTERM)", code)
	}
}

func TestRunKillsSealedThatIgnoresStop(t *testing.T) {
	f := newFixture(t, "ignore-term", 100*time.Millisecond)
	a, _ := f.version(t, "\nA\n")
	f.list.set(a)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 128+int(syscall.SIGKILL) {
		t.Fatalf("exit code %d, want %d (killed after the grace period)", code, 128+int(syscall.SIGKILL))
	}
}

// switchFixture: version A ran here before and runs first; the version it
// stages and asks for (B) is listed too.
func switchFixture(t *testing.T, mode string) (*fixture, string, string) {
	t.Helper()
	f := newFixture(t, mode, 5*time.Second)
	a, ab := f.version(t, "")
	exe, _ := os.Executable()
	b0, _ := os.ReadFile(exe)
	b := hashOf(append(b0, []byte("\nversion two\n")...))
	f.staged(t, a, ab)
	f.write(t, "current", a)
	f.write(t, "confirmed", a)
	f.list.set(a, b)
	t.Setenv(firstEnv, a)
	return f, a, b
}

// A switch: the running version asks, the loader stops it and starts the
// staged one on trial, which confirms; current and previous record it.
func TestRunSwitchesVersions(t *testing.T) {
	f, a, b := switchFixture(t, "switch")
	done := runAsync(f.s)
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGUSR1
	if code := f.stopWhenReady(t, done); code != 9 {
		t.Fatalf("exit code %d, want 9 (the switched-to version, confirmed, stopped)", code)
	}
	if f.s.state.hash("current") != b || f.s.state.hash("previous") != a || f.s.state.read("confirmed") != b {
		t.Fatalf("current %q previous %q confirmed %q", f.s.state.hash("current"), f.s.state.hash("previous"), f.s.state.read("confirmed"))
	}
	// The next start runs the switched-to version, no longer on trial.
	if v, ok := f.s.choose(); !ok || v.hash != b || f.s.trial(v) {
		t.Fatalf("next start %+v (%v), trial %v", v, ok, f.s.trial(v))
	}
}

// A switched-to version that exits before confirming sends the loader back
// to the version it replaced, and is not switched to again.
func TestRunGoesBackFromAVersionThatDoesNotComeUp(t *testing.T) {
	f, a, b := switchFixture(t, "switch-fail")
	done := runAsync(f.s)
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGUSR1
	if code := f.stopWhenReady(t, done); code != 4 {
		t.Fatalf("exit code %d, want 4 (the first version, run again after going back)", code)
	}
	if !f.s.state.failed(b) || f.s.state.hash("current") != a {
		t.Fatalf("failed %v, current %q", f.s.state.failed(b), f.s.state.hash("current"))
	}
	if _, ok := f.s.requested(version{hash: a}); ok {
		t.Fatal("the failed version would be switched to again")
	}
}

// A request whose staged program does not hash to its name is refused; the
// running sealed keeps running.
func TestRunRefusesABadRequest(t *testing.T) {
	f, a, _ := switchFixture(t, "bad-request")
	done := runAsync(f.s)
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGUSR1
	time.Sleep(50 * time.Millisecond)
	f.sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 3 {
		t.Fatalf("exit code %d, want 3 (stopped, never switched)", code)
	}
	if got := f.s.state.hash("current"); got != a {
		t.Fatalf("current %q after a refused switch", got)
	}
}

// A switch the loader's own list read cannot confirm is refused; the running
// sealed keeps running.
func TestRunRefusesASwitchTheListCannotConfirm(t *testing.T) {
	f, a, _ := switchFixture(t, "switch")
	f.list.refuseErr = true
	done := runAsync(f.s)
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGUSR1
	time.Sleep(50 * time.Millisecond)
	f.sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 0 {
		t.Fatalf("exit code %d, want 0 (stopped, never switched)", code)
	}
	if got := f.s.state.hash("current"); got != a {
		t.Fatalf("current %q after a refused switch", got)
	}
}

// A version on trial that exits for a reason outside it is started again,
// not marked failed, and is kept once it confirms.
func TestRunRetriesATransientTrialFailure(t *testing.T) {
	f, _, b := switchFixture(t, "switch-transient")
	done := runAsync(f.s)
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGUSR1
	if code := f.stopWhenReady(t, done); code != 3 {
		t.Fatalf("exit code %d, want 3 (the switched-to version, confirmed, stopped)", code)
	}
	if f.s.state.failed(b) || f.s.state.hash("current") != b || f.s.state.read("confirmed") != b {
		t.Fatalf("failed %v, current %q, confirmed %q", f.s.state.failed(b), f.s.state.hash("current"), f.s.state.read("confirmed"))
	}
	if got := f.s.state.read("runs"); got != "3" {
		t.Fatalf("the version ran %s times, want 3", got)
	}
}

// ... until transientLimit: then the loader goes back, where the version to
// go back to is listed.
func TestRunGoesBackAfterTransientFailuresOutlastTheLimit(t *testing.T) {
	f, a, b := switchFixture(t, "switch-transient")
	t.Setenv("LOADER_TEST_TRANSIENT_FOREVER", "1")
	f.s.transientLimit = 0
	done := runAsync(f.s)
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGUSR1
	if code := f.stopWhenReady(t, done); code != 4 {
		t.Fatalf("exit code %d, want 4 (the first version, run again after going back)", code)
	}
	if !f.s.state.failed(b) || f.s.state.hash("current") != a {
		t.Fatalf("failed %v, current %q", f.s.state.failed(b), f.s.state.hash("current"))
	}
}

// A version on trial that has not confirmed within trialLimit is stopped and
// gone back from.
func TestRunStopsATrialThatDoesNotConfirm(t *testing.T) {
	f, _, b := switchFixture(t, "switch-silent")
	f.s.trialLimit = 200 * time.Millisecond
	done := runAsync(f.s)
	waitReady(t, f.ready)
	f.sigs <- syscall.SIGUSR1
	if code := f.stopWhenReady(t, done); code != 4 {
		t.Fatalf("exit code %d, want 4 (the first version, run again after going back)", code)
	}
	if !f.s.state.failed(b) {
		t.Fatalf("%s not recorded as failed", b)
	}
}

// A sealed that came up and exits on its own is restarted.
func TestRunRestartsACrashedSealed(t *testing.T) {
	f := newFixture(t, "crash", 5*time.Second)
	a, _ := f.version(t, "\nA\n")
	f.list.set(a)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0 (the restarted sealed, stopped)", code)
	}
	if got := f.s.state.read("runs"); got != "2" {
		t.Fatalf("sealed ran %s times, want 2", got)
	}
}

// ... a bounded number of times.
func TestRunGivesUpOnASealedThatKeepsExiting(t *testing.T) {
	f := newFixture(t, "crash-loop", 5*time.Second)
	a, _ := f.version(t, "\nA\n")
	f.list.set(a)
	if code := waitCode(t, runAsync(f.s)); code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if got := f.s.state.read("runs"); got != strconv.Itoa(maxRestarts+1) {
		t.Fatalf("sealed ran %s times, want %d", got, maxRestarts+1)
	}
}

// A sealed that exits because its owner asked for a restart is started
// again at once, however often.
func TestRunRestartsOnRequestWithoutCounting(t *testing.T) {
	f := newFixture(t, "owner-restart", 5*time.Second)
	a, _ := f.version(t, "\nA\n")
	f.list.set(a)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0 (running after the restarts, stopped)", code)
	}
	if got := f.s.state.read("runs"); got != strconv.Itoa(maxRestarts+3) {
		t.Fatalf("sealed ran %s times, want %d", got, maxRestarts+3)
	}
}

func TestFetchSealed(t *testing.T) {
	d := stateDir(filepath.Join(t.TempDir(), "loader"))
	if err := d.prepare(); err != nil {
		t.Fatal(err)
	}
	body := []byte("a sealed program")
	h := hashOf(body)
	big := strings.Repeat("x", maxSealedBytes+1)
	redirects := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case h:
			_, _ = w.Write(body)
		case "loop":
			redirects++
			http.Redirect(w, r, "/loop", http.StatusFound)
		case hashOf([]byte(big)):
			_, _ = io.WriteString(w, big)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newArtifactClient()
	if err := fetchSealed(c, srv.URL, d, h); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if verifyFile(d.staged(h), h) != nil {
		t.Fatal("not kept under its hash")
	}
	if err := fetchSealed(c, srv.URL, d, strings.Repeat("0", 64)); err == nil {
		t.Fatal("a 404 fetched")
	}
	if err := download(c, srv.URL+"/loop", filepath.Join(t.TempDir(), "x"), h); err == nil || redirects > maxRedirects+1 {
		t.Fatalf("redirect loop: %v after %d redirects", err, redirects)
	}
	if err := fetchSealed(c, srv.URL, d, hashOf([]byte(big))); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(d.staged(h)))
	if len(entries) != 1 {
		t.Fatalf("left %d files in the staging directory, want the one fetched", len(entries))
	}
}

// The loader downloads from where sealed does (internal/layers ArtifactsURL),
// which the loader does not link.
func TestArtifactsURLMatchesSealed(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "layers", "artifacts.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`var ArtifactsURL = "([^"]+)"`).FindSubmatch(src)
	if m == nil || string(m[1]) != artifactsURL {
		t.Fatalf("sealed's ArtifactsURL %q, the loader's %q", m, artifactsURL)
	}
}

func TestTransientRetryBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 4: 4 * time.Minute, 5: 5 * time.Minute, 50: 5 * time.Minute} {
		if got := transientRetryBackoff(n); got != want {
			t.Errorf("transientRetryBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestStateFiles(t *testing.T) {
	d := stateDir(filepath.Join(t.TempDir(), "loader"))
	if err := d.prepare(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(string(d)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state dir: %v %v", fi.Mode(), err)
	}
	h := strings.Repeat("ab", 32)
	if err := d.write("current", h+"\n"); err != nil {
		t.Fatal(err)
	}
	if d.hash("current") != h {
		t.Fatalf("hash %q", d.hash("current"))
	}
	for _, bad := range []string{"", "nope", strings.ToUpper(h), h[:62]} {
		_ = d.write("current", bad)
		if d.hash("current") != "" {
			t.Fatalf("%q read as a hash", bad)
		}
	}
	if d.failed(h) || d.mismatched(h) {
		t.Fatal("listed before being added")
	}
	_ = d.markFailed(h)
	_ = d.markFailed(strings.Repeat("cd", 32))
	_ = d.markFailed(h)
	if !d.failed(h) || !d.failed(strings.Repeat("cd", 32)) || strings.Count(d.read("failed"), h) != 1 {
		t.Fatalf("failed holds %q", d.read("failed"))
	}
	_ = d.markMismatched(h)
	if !d.mismatched(h) || d.mismatched(strings.Repeat("cd", 32)) {
		t.Fatalf("mismatched holds %q", d.read("mismatched"))
	}
}

// TestLinkedPackages keeps the loader small: as PID 1 it holds the same
// environment as sealed, so anything beyond the standard library and
// golang.org/x/sys/unix linked into it needs a deliberate review.
func TestLinkedPackages(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	got := strings.Fields(string(out))
	sort.Strings(got)
	want := []string{"golang.org/x/sys/unix", "seal-verify/cmd/loader"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loader links %v, want %v", got, want)
	}
}
