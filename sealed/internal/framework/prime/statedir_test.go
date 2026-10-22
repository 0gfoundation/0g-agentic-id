package prime

import (
	"fmt"
	"os"
	"testing"

	"seal-verify/internal/framework"
)

// TestMain points framework.StateDir at a scratch directory for the whole
// package, so no test ever writes sealed's real state directory.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sealed-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	framework.StateDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// isolateState gives one test its own framework.StateDir, so state an
// adapter keeps there (overlay records, conversation identities) never
// leaks between tests.
func isolateState(t *testing.T) {
	t.Helper()
	prev := framework.StateDir
	framework.StateDir = t.TempDir()
	t.Cleanup(func() { framework.StateDir = prev })
}
