//go:build linux

package privsep

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The security tests here need root (they chown to a foreign uid, build
// root-only fixtures and start processes as another uid). Run as anyone
// else they skip, which `go test` reports as ok; with
// SEALED_PRIVSEP_TESTS=1 — the documented way to run them, as root in a
// Linux container (AGENTS.md) — a test that cannot run its key branch
// fails instead.
func strictPrivsepTests() bool { return os.Getenv("SEALED_PRIVSEP_TESTS") == "1" }

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if strictPrivsepTests() {
		t.Fatalf("SEALED_PRIVSEP_TESTS=1, but: "+format, args...)
	}
	t.Skipf(format, args...)
}

// requireRoot skips (or, strict, fails) tests that need root.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		skipOrFail(t, "needs root (chown to a foreign uid, processes as another uid)")
	}
}

// testUID is the stand-in agent identity the tests use.
const testUID = 4242

// withAgentCred makes credential() report a stand-in agent account (uid
// and gid testUID) for the rest of the test, so the split's code paths run
// on machines without an agent account.
func withAgentCred(t *testing.T) *syscall.Credential {
	t.Helper()
	c := &syscall.Credential{Uid: testUID, Gid: testUID, Groups: []uint32{}}
	prev := testCred
	testCred = c
	t.Cleanup(func() { testCred = prev })
	return c
}

// withHomeState sets the recorded SecureHome / PrepareAgentHome outcome for
// the rest of the test.
// ReclaimHome, and HardenSelf's no_new_privs, are recorded as having
// succeeded exactly when SecureHome did; withReclaimState and
// withSelfState override that.
func withHomeState(t *testing.T, secured bool, secErr error, ready bool, prepErr error) {
	t.Helper()
	homeMu.Lock()
	ps, pse, pr, ppe, prc, prce := homeSecured, homeErr, agentReady, agentErr, reclaimed, reclaimErr
	pn, pne := noNewPrivs, noNewPrivsErr
	homeSecured, homeErr, agentReady, agentErr = secured, secErr, ready, prepErr
	reclaimed, reclaimErr = secured, nil
	noNewPrivs, noNewPrivsErr = secured, nil
	homeMu.Unlock()
	t.Cleanup(func() {
		homeMu.Lock()
		homeSecured, homeErr, agentReady, agentErr, reclaimed, reclaimErr = ps, pse, pr, ppe, prc, prce
		noNewPrivs, noNewPrivsErr = pn, pne
		homeMu.Unlock()
	})
}

// withSelfState sets the recorded no_new_privs outcome; call it after
// withHomeState, whose cleanup restores it.
func withSelfState(t *testing.T, set bool, err error) {
	t.Helper()
	homeMu.Lock()
	noNewPrivs, noNewPrivsErr = set, err
	homeMu.Unlock()
}

// withReclaimState sets the recorded ReclaimHome outcome; call it after
// withHomeState, whose cleanup restores it.
func withReclaimState(t *testing.T, done bool, err error) {
	t.Helper()
	homeMu.Lock()
	reclaimed, reclaimErr = done, err
	homeMu.Unlock()
}

// withAgentHome points agentHomeDir at a fresh directory the stand-in
// agent owns and can reach (its ancestors are made traversable), for the
// rest of the test. Needs root.
func withAgentHome(t *testing.T) string {
	t.Helper()
	requireRoot(t)
	base := t.TempDir()
	for d := base; d != "/" && d != os.TempDir(); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(base, "agent")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	prev := agentHomeDir
	agentHomeDir = home
	t.Cleanup(func() { agentHomeDir = prev })
	return home
}
