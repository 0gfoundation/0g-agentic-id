package proxy

import (
	"os"
	"testing"

	"seal-verify/internal/servicesandbox"
)

// The hosted-service launcher is the running program (privsep.RootSelf); in
// these tests that is the test binary, which dispatches the launcher mode as
// sealed's main does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == servicesandbox.LauncherMode {
		os.Exit(servicesandbox.Launch(os.Args[2:]))
	}
	os.Exit(m.Run())
}
