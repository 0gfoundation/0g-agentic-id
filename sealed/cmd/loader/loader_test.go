package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	helperEnv = "LOADER_TEST_HELPER"
	readyEnv  = "LOADER_TEST_READY"
)

// TestMain doubles as the sealed the tests supervise: with LOADER_TEST_HELPER
// set, the test binary acts out the named mode instead of running tests.
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
	}
	os.Exit(2)
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

func helper(t *testing.T, mode string, grace time.Duration) (*supervisor, chan os.Signal, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	readyFile := filepath.Join(t.TempDir(), "ready")
	// sealed inherits the loader's environment, so the helper mode travels
	// the same way.
	t.Setenv(helperEnv, mode)
	t.Setenv(readyEnv, readyFile)
	sigs := make(chan os.Signal, 4)
	return &supervisor{
		path:      exe,
		stdout:    io.Discard,
		stderr:    io.Discard,
		sigs:      sigs,
		stopGrace: grace,
		poll:      10 * time.Millisecond,
		logf:      t.Logf,
	}, sigs, readyFile
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
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor did not return")
		return 0
	}
}

func TestRunReturnsSealedExitCode(t *testing.T) {
	s, _, _ := helper(t, "exit7", time.Second)
	if code := waitCode(t, runAsync(s)); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}

func TestRunForwardsStopSignal(t *testing.T) {
	s, sigs, readyFile := helper(t, "term3", 5*time.Second)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 3 {
		t.Fatalf("exit code %d, want 3 (the helper's own exit on SIGTERM)", code)
	}
}

func TestRunKillsSealedThatIgnoresStop(t *testing.T) {
	s, sigs, readyFile := helper(t, "ignore-term", 100*time.Millisecond)
	done := runAsync(s)
	waitReady(t, readyFile)
	sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 128+int(syscall.SIGKILL) {
		t.Fatalf("exit code %d, want %d (killed after the grace period)", code, 128+int(syscall.SIGKILL))
	}
}

func TestRunReportsStartFailure(t *testing.T) {
	s, _, _ := helper(t, "exit7", time.Second)
	s.path = filepath.Join(t.TempDir(), "missing")
	if code := waitCode(t, runAsync(s)); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
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
