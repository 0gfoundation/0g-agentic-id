package servicehost

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/privsep"
	"seal-verify/internal/servicesandbox"
)

// relocatedEnv marks the run of this test binary from a root-only copy.
const relocatedEnv = "SEALED_SERVICEHOST_TEST_RELOCATED"

// The launcher is the program that runs the manager (privsep.RootSelf); in
// these tests that is the test binary, which dispatches the launcher mode as
// sealed's main does. RootSelf runs only a root-owned file in root-only
// directories, and go test builds into a temporary directory anyone can
// write, so the tests that start the real launcher (SEALED_SERVICE_TESTS=1,
// as root) run from a copy in a root-only directory under /var/lib.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == servicesandbox.LauncherMode {
		os.Exit(servicesandbox.Launch(os.Args[2:]))
	}
	if os.Geteuid() == 0 && os.Getenv("SEALED_SERVICE_TESTS") == "1" && os.Getenv(relocatedEnv) == "" {
		os.Exit(runRelocated())
	}
	os.Exit(m.Run())
}

func runRelocated() int {
	self, err := os.Executable()
	if err != nil {
		os.Stderr.WriteString("relocate the test binary: " + err.Error() + "\n")
		return 2
	}
	dir, err := os.MkdirTemp("/var/lib", "servicehost-test-")
	if err != nil {
		os.Stderr.WriteString("relocate the test binary: " + err.Error() + "\n")
		return 2
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, filepath.Base(self))
	if err := copyExecutable(self, copyPath); err != nil {
		os.Stderr.WriteString("relocate the test binary: " + err.Error() + "\n")
		return 2
	}
	cmd := exec.Command(copyPath, os.Args[1:]...)
	cmd.Env = append(os.Environ(), relocatedEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	var exit *exec.ExitError
	switch err := cmd.Run(); {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	default:
		os.Stderr.WriteString("run the relocated test binary: " + err.Error() + "\n")
		return 2
	}
}

func copyExecutable(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// The launcher is this program: RootSelf runs its own executable with the
// launcher mode first, and refuses one another uid could have written.
func TestLauncherIsTheRunningProgram(t *testing.T) {
	root(t)
	if os.Getenv(relocatedEnv) == "" {
		t.Skip("set SEALED_SERVICE_TESTS=1 as root: the test binary then runs from a root-only copy")
	}
	cmd, err := privsep.RootSelf(context.Background(), servicesandbox.LauncherMode, "probe")
	self, _ := os.Executable()
	selfReal, _ := filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != selfReal || len(cmd.Args) < 3 || cmd.Args[1] != servicesandbox.LauncherMode || cmd.Args[2] != "probe" {
		t.Fatalf("launcher command %s %q, want %s with %s probe", cmd.Path, cmd.Args, selfReal, servicesandbox.LauncherMode)
	}
	// The launcher refuses anything but root before it does anything.
	out, err := exec.Command(selfReal, servicesandbox.LauncherMode, "nonsense").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "unknown mode") {
		t.Fatalf("unknown mode: %v %s", err, out)
	}
}
