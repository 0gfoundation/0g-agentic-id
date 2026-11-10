// Command loader is PID 1 in the layered 0g-harness image (sealed/LAYERS.md).
// It checks the sealed binary against the hash built into it, runs sealed as
// its child, forwards stop signals to it, reaps orphaned processes, and exits
// with sealed's status once sealed exits.
//
// sealed obtains the agent identity key once it runs, so the check comes
// before exec: a check made afterwards would be a claim by the code being
// checked. The expected hash is fixed when the image is built
// (-ldflags "-X main.expectedSealedHash=<sha256 hex>"), and the image holds
// both binaries, so the image hash covers the pair.
//
// The environment, container key included, goes to sealed unchanged: sealed
// reads and scrubs it exactly as it does when it is PID 1 itself. Like
// sealed, the loader is root, non-dumpable and sets no_new_privs, so another
// uid cannot read it from /proc/1/environ.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// expectedSealedHash is the lowercase hex sha256 of the only sealed binary
// this loader runs, set at build time. Empty means the build did not set it,
// and the loader then runs nothing.
var expectedSealedHash = ""

// sealedPath is where the image puts the sealed binary.
const sealedPath = "/bootstrap"

func main() {
	harden()
	if err := verifyFile(sealedPath, expectedSealedHash); err != nil {
		logf("FAIL %v", err)
		os.Exit(1)
	}
	logf("OK   %s matches the sealed hash built into the loader (%s)", sealedPath, expectedSealedHash)

	// Registered before sealed starts, so its exit cannot slip past.
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGCHLD)

	s := &supervisor{
		path:      sealedPath,
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		reapAll:   os.Getpid() == 1,
		sigs:      sigs,
		stopGrace: stopGrace,
		poll:      time.Second,
		logf:      logf,
	}
	os.Exit(s.run())
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "loader: "+format+"\n", a...)
}
