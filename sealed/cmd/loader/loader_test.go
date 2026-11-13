package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	helperEnv  = "LOADER_TEST_HELPER"
	readyEnv   = "LOADER_TEST_READY"
	stateEnv   = "LOADER_TEST_STATE"
	builtinEnv = "LOADER_TEST_BUILTIN"
)

// TestMain doubles as the sealed the tests supervise: with LOADER_TEST_HELPER
// set, the test binary acts out the named mode instead of running tests.
// A staged copy of the binary runs the same modes; SEALED_HASH, set by the
// loader, tells it which version it is.
func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "exit7":
		os.Exit(7)
	case "term3":
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		ready()
		<-c
		os.Exit(3)
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		ready()
		time.Sleep(time.Minute)
		os.Exit(0)
	case "switch", "switch-fail", "switch-transient", "switch-silent":
		helperSwitch()
	case "report":
		// Writes which version it is and which it stands in for, then exits 7.
		state := os.Getenv(stateEnv)
		_ = os.WriteFile(filepath.Join(state, "report"), []byte(os.Getenv(sealedHashEnv)+" "+os.Getenv(insteadOfEnv)), 0o600)
		os.Exit(7)
	case "go-back":
		// The image's version, standing in for another, asks to go back to
		// it and waits to be stopped; the version gone back to exits 9.
		state := os.Getenv(stateEnv)
		if os.Getenv(sealedHashEnv) != os.Getenv(builtinEnv) {
			os.Exit(9)
		}
		_ = os.WriteFile(filepath.Join(state, "request"), []byte(os.Getenv(insteadOfEnv)), 0o600)
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		ready()
		<-c
		os.Exit(0)
	case "owner-restart":
		// Exits for an owner restart more often than a crash is allowed to,
		// then waits to be stopped.
		state := os.Getenv(stateEnv)
		_ = os.WriteFile(filepath.Join(state, "layered"), []byte("1"), 0o600)
		runs := filepath.Join(state, "runs")
		n, _ := strconv.Atoi(readTrim(runs))
		_ = os.WriteFile(runs, []byte(strconv.Itoa(n+1)), 0o600)
		if n+1 <= maxRestarts+2 {
			os.Exit(restartRequestedExit)
		}
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		ready()
		<-c
		os.Exit(0)
	case "bad-request":
		state := os.Getenv(stateEnv)
		_ = os.WriteFile(filepath.Join(state, "request"), []byte(strings.Repeat("ab", 32)), 0o600)
		_ = os.MkdirAll(filepath.Join(state, "sealed"), 0o700)
		_ = os.WriteFile(filepath.Join(state, "sealed", strings.Repeat("ab", 32)), []byte("not it"), 0o500)
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		ready()
		<-c
		os.Exit(3)
	case "crash", "crash-loop":
		state := os.Getenv(stateEnv)
		_ = os.WriteFile(filepath.Join(state, "layered"), []byte("1"), 0o600)
		runs := filepath.Join(state, "runs")
		n, _ := strconv.Atoi(readTrim(runs))
		_ = os.WriteFile(runs, []byte(strconv.Itoa(n+1)), 0o600)
		if os.Getenv(helperEnv) == "crash" && n+1 == 2 {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGTERM)
			ready()
			<-c
			os.Exit(0)
		}
		os.Exit(3)
	}
	os.Exit(2)
}

// helperSwitch: the image's version stages a second version (this binary
// with bytes appended, so another hash) and asks to switch, then waits to be
// stopped; the second version confirms and exits 9, or, in switch-fail,
// exits 75 without confirming; in switch-transient it exits
// trialTransientExit on its first two starts (on every start with
// LOADER_TEST_TRANSIENT_FOREVER), then confirms and waits to be stopped
// (exit 3); in switch-silent it never confirms and exits 0 when stopped. Run
// again after going back, the image's version exits 4.
func helperSwitch() {
	state := os.Getenv(stateEnv)
	if os.Getenv(sealedHashEnv) != os.Getenv(builtinEnv) {
		switch os.Getenv(helperEnv) {
		case "switch-fail":
			os.Exit(75)
		case "switch-transient":
			_ = os.WriteFile(filepath.Join(state, "layered"), []byte("1"), 0o600)
			runs := filepath.Join(state, "runs")
			n, _ := strconv.Atoi(readTrim(runs))
			_ = os.WriteFile(runs, []byte(strconv.Itoa(n+1)), 0o600)
			if n+1 <= 2 || os.Getenv("LOADER_TEST_TRANSIENT_FOREVER") != "" {
				os.Exit(trialTransientExit)
			}
			if os.Getenv(trialEnv) != "1" {
				os.Exit(8)
			}
			_ = os.WriteFile(filepath.Join(state, "confirmed"), []byte(os.Getenv(sealedHashEnv)), 0o600)
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGTERM)
			ready()
			<-c
			os.Exit(3)
		case "switch-silent":
			_ = os.WriteFile(filepath.Join(state, "layered"), []byte("1"), 0o600)
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGTERM)
			<-c
			os.Exit(0)
		}
		if os.Getenv(trialEnv) != "1" {
			os.Exit(8) // a switched-to version must start on trial
		}
		_ = os.WriteFile(filepath.Join(state, "confirmed"), []byte(os.Getenv(sealedHashEnv)), 0o600)
		os.Exit(9)
	}
	if readTrim(filepath.Join(state, "failed")) != "" {
		os.Exit(4)
	}
	exe, _ := os.Executable()
	b, _ := os.ReadFile(exe)
	b = append(b, []byte("\nversion two\n")...)
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	_ = os.MkdirAll(filepath.Join(state, "sealed"), 0o700)
	_ = os.WriteFile(filepath.Join(state, "sealed", h), b, 0o700)
	_ = os.WriteFile(filepath.Join(state, "request"), []byte(h), 0o600)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	ready()
	<-c
	os.Exit(0)
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

// ready tells the test the helper has installed its signal handling.
func ready() {
	if p := os.Getenv(readyEnv); p != "" {
		_ = os.WriteFile(p, nil, 0o600)
	}
}

func TestVerifyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.WriteFile(p, []byte("sealed build"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("sealed build"))
	good := hex.EncodeToString(sum[:])

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

// helper builds a supervisor whose image sealed is this test binary in the
// given mode; withState gives it a state directory.
func helper(t *testing.T, mode string, grace time.Duration, withState bool) (*supervisor, chan os.Signal, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:])
	readyFile := filepath.Join(t.TempDir(), "ready")
	// sealed inherits the loader's environment, so the helper mode travels
	// the same way.
	t.Setenv(helperEnv, mode)
	t.Setenv(readyEnv, readyFile)
	t.Setenv(builtinEnv, hash)
	t.Setenv(sealedHashEnv, "")
	t.Setenv(trialEnv, "")
	t.Setenv(insteadOfEnv, "")
	sigs := make(chan os.Signal, 4)
	s := &supervisor{
		builtin:          version{hash: hash, path: exe},
		allow:            listAll{},
		stdout:           io.Discard,
		stderr:           io.Discard,
		sigs:             sigs,
		stopGrace:        grace,
		poll:             10 * time.Millisecond,
		backoff:          func(int) time.Duration { return 0 },
		window:           time.Minute,
		trialLimit:       time.Minute,
		transientLimit:   time.Hour,
		transientBackoff: func(int) time.Duration { return 0 },
		logf:             t.Logf,
	}
	if withState {
		dir := filepath.Join(t.TempDir(), "loader")
		s.state = stateDir(dir)
		if err := s.state.prepare(); err != nil {
			t.Fatal(err)
		}
		t.Setenv(stateEnv, dir)
	}
	return s, sigs, readyFile
}

// listAll is a sealed list that lists every version.
type listAll struct{}

func (listAll) refuses(string) (bool, error) { return false, nil }

// listFunc is a sealed list that answers with a function.
type listFunc func(hash string) (bool, error)

func (f listFunc) refuses(hash string) (bool, error) { return f(hash) }

// unreadable is the answer of a list the loader cannot read.
var errUnreadable = errors.New("rpc down")

// stageCopy stages a copy of this test binary with suffix appended (so
// another hash) as the recorded current version, confirmed.
func stageCopy(t *testing.T, s *supervisor, suffix string) string {
	t.Helper()
	exe, _ := os.Executable()
	b, _ := os.ReadFile(exe)
	b = append(b, []byte(suffix)...)
	sum := sha256.Sum256(b)
	staged := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(string(s.state), "sealed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.state.staged(staged), b, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"current": staged, "confirmed": staged, "previous": ""} {
		if err := s.state.write(name, v); err != nil {
			t.Fatal(err)
		}
	}
	return staged
}

func runAsync(s *supervisor) <-chan int {
	done := make(chan int, 1)
	go func() { done <- s.run() }()
	return done
}

func waitReady(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
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
	case <-time.After(20 * time.Second):
		t.Fatal("supervisor did not return")
		return 0
	}
}

func TestRunReturnsSealedExitCode(t *testing.T) {
	s, _, _ := helper(t, "exit7", time.Second, false)
	if code := waitCode(t, runAsync(s)); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}

// Without the layered flow, a sealed that exits ends the loader even with a
// state directory.
func TestRunExitsWithSealedWithoutTheLayeredFlow(t *testing.T) {
	s, _, _ := helper(t, "exit7", time.Second, true)
	if code := waitCode(t, runAsync(s)); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}

func TestRunForwardsStopSignal(t *testing.T) {
	s, sigs, readyFile := helper(t, "term3", 5*time.Second, true)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 3 {
		t.Fatalf("exit code %d, want 3 (the helper's own exit on SIGTERM)", code)
	}
}

func TestRunKillsSealedThatIgnoresStop(t *testing.T) {
	s, sigs, readyFile := helper(t, "ignore-term", 100*time.Millisecond, false)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 128+int(syscall.SIGKILL) {
		t.Fatalf("exit code %d, want %d (killed after the grace period)", code, 128+int(syscall.SIGKILL))
	}
}

func TestRunReportsStartFailure(t *testing.T) {
	s, _, _ := helper(t, "exit7", time.Second, false)
	s.builtin.path = filepath.Join(t.TempDir(), "missing")
	if code := waitCode(t, runAsync(s)); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
}

// A switch: the running version asks, the loader stops it and starts the
// staged one on trial, which confirms; current and previous record it.
func TestRunSwitchesVersions(t *testing.T) {
	s, sigs, readyFile := helper(t, "switch", 5*time.Second, true)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGUSR1
	if code := waitCode(t, done); code != 9 {
		t.Fatalf("exit code %d, want 9 (the switched-to version, confirmed)", code)
	}
	next := s.state.hash("request")
	if next == "" || next == s.builtin.hash {
		t.Fatalf("request %q", next)
	}
	if got := s.state.hash("current"); got != next {
		t.Fatalf("current %q, want %q", got, next)
	}
	if got := s.state.hash("previous"); got != s.builtin.hash {
		t.Fatalf("previous %q, want the image's version", got)
	}
	if got := s.state.read("confirmed"); got != next {
		t.Fatalf("confirmed %q", got)
	}
	// The next start runs the switched-to version, no longer on trial.
	if cur := s.current(); cur.hash != next || s.trial(cur) {
		t.Fatalf("current %+v, trial %v", cur, s.trial(cur))
	}
}

// A switched-to version that exits before confirming sends the loader back
// to the version it replaced, and is not switched to again.
func TestRunGoesBackFromAVersionThatDoesNotComeUp(t *testing.T) {
	s, sigs, readyFile := helper(t, "switch-fail", 5*time.Second, true)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGUSR1
	if code := waitCode(t, done); code != 4 {
		t.Fatalf("exit code %d, want 4 (the image's version, run again after going back)", code)
	}
	failed := s.state.hash("request")
	if !s.state.failed(failed) {
		t.Fatalf("%s not recorded as failed", failed)
	}
	if got := s.state.hash("current"); got != s.builtin.hash {
		t.Fatalf("current %q, want the image's version", got)
	}
	if _, ok := s.requested(s.builtin); ok {
		t.Fatal("the failed version would be switched to again")
	}
}

// A request whose staged program does not hash to its name is refused; the
// running sealed keeps running.
func TestRunRefusesABadRequest(t *testing.T) {
	s, sigs, readyFile := helper(t, "bad-request", 5*time.Second, true)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGUSR1
	time.Sleep(50 * time.Millisecond)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 3 {
		t.Fatalf("exit code %d, want 3 (stopped, never switched)", code)
	}
	if got := s.state.hash("current"); got != "" {
		t.Fatalf("current %q after a refused switch", got)
	}
}

// Under the layered flow a sealed that exits on its own is restarted.
func TestRunRestartsSealedUnderTheLayeredFlow(t *testing.T) {
	s, sigs, readyFile := helper(t, "crash", 5*time.Second, true)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 0 {
		t.Fatalf("exit code %d, want 0 (the restarted sealed, stopped)", code)
	}
	if got := s.state.read("runs"); got != "2" {
		t.Fatalf("sealed ran %s times, want 2", got)
	}
}

// ... a bounded number of times.
func TestRunGivesUpOnASealedThatKeepsExiting(t *testing.T) {
	s, _, _ := helper(t, "crash-loop", 5*time.Second, true)
	if code := waitCode(t, runAsync(s)); code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if got := s.state.read("runs"); got != strconv.Itoa(maxRestarts+1) {
		t.Fatalf("sealed ran %s times, want %d", got, maxRestarts+1)
	}
}

// The list cannot be read: the recorded version does not run, the image's
// own runs in its place and is told which one that is, and nothing recorded
// changes, so the next start tries the recorded version again.
func TestRunStandsInForAVersionTheListCannotConfirm(t *testing.T) {
	s, _, _ := helper(t, "report", time.Second, true)
	staged := stageCopy(t, s, "\nstaged\n")
	s.allow = listFunc(func(string) (bool, error) { return false, errUnreadable })
	if code := waitCode(t, runAsync(s)); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	if got, want := s.state.read("report"), s.builtin.hash+" "+staged; got != want {
		t.Fatalf("ran %q, want the image's own in place of the staged one %q", got, want)
	}
	if got := s.state.hash("current"); got != staged {
		t.Fatalf("current %q, want the staged version still recorded", got)
	}

	// Readable again: the recorded version runs, standing in for nothing.
	s.allow = listAll{}
	if code := waitCode(t, runAsync(s)); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	if got := s.state.read("report"); got != staged {
		t.Fatalf("ran %q, want %q standing in for nothing", got, staged)
	}
}

// The image's own, standing in, asks to go back to the version it stands in
// for once the list reads it as listed: the loader switches, and that version
// keeps the version it had replaced.
func TestRunGoesBackToTheVersionStoodInFor(t *testing.T) {
	s, sigs, readyFile := helper(t, "go-back", 5*time.Second, true)
	staged := stageCopy(t, s, "\nstaged\n")
	older := strings.Repeat("ab", 32)
	if err := s.state.write("previous", older); err != nil {
		t.Fatal(err)
	}
	var readable atomic.Bool
	s.allow = listFunc(func(h string) (bool, error) {
		if !readable.Load() {
			return false, errUnreadable
		}
		return false, nil
	})
	done := runAsync(s)
	waitReady(t, readyFile)
	readable.Store(true)
	sigs <- syscall.SIGUSR1
	if code := waitCode(t, done); code != 9 {
		t.Fatalf("exit code %d, want 9 (the version gone back to)", code)
	}
	if got := s.state.hash("current"); got != staged {
		t.Fatalf("current %q, want %q", got, staged)
	}
	if got := s.state.hash("previous"); got != older {
		t.Fatalf("previous %q, want the one it had replaced %q", got, older)
	}
}

// A switch the loader's own list read cannot confirm is refused; the running
// sealed keeps running.
func TestRunRefusesASwitchTheListCannotConfirm(t *testing.T) {
	s, sigs, readyFile := helper(t, "switch", 5*time.Second, true)
	s.allow = listFunc(func(h string) (bool, error) {
		if h == s.builtin.hash {
			return false, nil
		}
		return false, errUnreadable
	})
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGUSR1
	time.Sleep(50 * time.Millisecond)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 0 {
		t.Fatalf("exit code %d, want 0 (stopped, never switched)", code)
	}
	if got := s.state.hash("current"); got != "" {
		t.Fatalf("current %q after a refused switch", got)
	}
}

// The image's own is explicitly not listed and the others cannot be read:
// the loader reads again later instead of giving up.
func TestRunReadsAgainWhenOnlyTheUnreadableMayBeListed(t *testing.T) {
	s, _, _ := helper(t, "report", time.Second, true)
	staged := stageCopy(t, s, "\nstaged\n")
	reads := 0
	s.allow = listFunc(func(h string) (bool, error) {
		reads++
		if h == s.builtin.hash {
			return true, nil
		}
		if reads < 4 {
			return false, errUnreadable
		}
		return false, nil
	})
	if code := waitCode(t, runAsync(s)); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	if got := s.state.read("report"); got != staged {
		t.Fatalf("ran %q, want the staged version once readable %q", got, staged)
	}
}

// A version on trial that exits for a reason outside it is started again,
// not marked failed, and is kept once it confirms.
func TestRunRetriesATransientTrialFailure(t *testing.T) {
	s, sigs, readyFile := helper(t, "switch-transient", 5*time.Second, true)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGUSR1
	waitReady(t, readyFile)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 3 {
		t.Fatalf("exit code %d, want 3 (the switched-to version, confirmed, stopped)", code)
	}
	next := s.state.hash("request")
	if s.state.failed(next) || s.state.hash("current") != next || s.state.read("confirmed") != next {
		t.Fatalf("failed %v, current %q, confirmed %q", s.state.failed(next), s.state.hash("current"), s.state.read("confirmed"))
	}
	if got := s.state.read("runs"); got != "3" {
		t.Fatalf("the version ran %s times, want 3", got)
	}
}

// ... until transientLimit: then the loader goes back, where the version to
// go back to is listed.
func TestRunGoesBackAfterTransientFailuresOutlastTheLimit(t *testing.T) {
	s, sigs, readyFile := helper(t, "switch-transient", 5*time.Second, true)
	t.Setenv("LOADER_TEST_TRANSIENT_FOREVER", "1")
	s.transientLimit = 0
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGUSR1
	if code := waitCode(t, done); code != 4 {
		t.Fatalf("exit code %d, want 4 (the image's version, run again after going back)", code)
	}
	if failed := s.state.hash("request"); !s.state.failed(failed) {
		t.Fatalf("%s not recorded as failed", failed)
	}
	if got := s.state.hash("current"); got != s.builtin.hash {
		t.Fatalf("current %q, want the image's version", got)
	}
}

// A version on trial that has not confirmed within trialLimit is stopped and
// gone back from.
func TestRunStopsATrialThatDoesNotConfirm(t *testing.T) {
	s, sigs, readyFile := helper(t, "switch-silent", 5*time.Second, true)
	s.trialLimit = 200 * time.Millisecond
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGUSR1
	if code := waitCode(t, done); code != 4 {
		t.Fatalf("exit code %d, want 4 (the image's version, run again after going back)", code)
	}
	if failed := s.state.hash("request"); !s.state.failed(failed) {
		t.Fatalf("%s not recorded as failed", failed)
	}
}

// A sealed that exits because its owner asked for a restart is started
// again at once, however often.
func TestRunRestartsOnRequestWithoutCounting(t *testing.T) {
	s, sigs, readyFile := helper(t, "owner-restart", 5*time.Second, true)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 0 {
		t.Fatalf("exit code %d, want 0 (running after the restarts, stopped)", code)
	}
	if got := s.state.read("runs"); got != strconv.Itoa(maxRestarts+3) {
		t.Fatalf("sealed ran %s times, want %d", got, maxRestarts+3)
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
	if d.failed(h) {
		t.Fatal("failed before markFailed")
	}
	_ = d.markFailed(h)
	_ = d.markFailed(strings.Repeat("cd", 32))
	_ = d.markFailed(h)
	if !d.failed(h) || !d.failed(strings.Repeat("cd", 32)) || strings.Count(d.read("failed"), h) != 1 {
		t.Fatalf("failed holds %q", d.read("failed"))
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
