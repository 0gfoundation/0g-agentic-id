// Command loader is PID 1 in the layered 0g-harness image (sealed/LAYERS.md).
// It runs sealed as its child, after checking the program against its hash,
// forwards stop signals to it, reaps orphaned processes, and exits with
// sealed's status once sealed exits.
//
// sealed obtains the agent identity key once it runs, so the check comes
// before exec: a check made afterwards would be a claim by the code being
// checked. The image's own sealed (/bootstrap) is checked against the hash
// built into the loader (-ldflags "-X main.expectedSealedHash=<sha256 hex>");
// the image holds both binaries, so the image hash covers the pair.
//
// Before it runs any sealed, the loader also asks the chain whether that
// version is on the trust registry's sealed list (allowlist.go). A version
// sealed downloaded runs only when the chain says it is listed; when no
// answer can be had, the image's own sealed runs in its place, and the
// version it stands in for is named to it (SEALED_INSTEAD_OF), so that once
// the list reads again it can ask to go back. One the chain says is not
// listed does not run at all.
//
// Under the layered flow (once sealed says the attestor runs it) the loader
// also switches sealed versions in place: sealed stages the version to run
// (the owner's pick, or the newest listed one when its own is delisted) in
// the loader's state directory, which only root can enter, after checking it
// against the list and its hash, and asks for the switch (SIGUSR1). The
// loader hashes the staged program again, checks the list itself, stops the
// running sealed, ends whatever it left behind, and starts the new one on
// trial; if that one exits before it confirms it came up, or has not
// confirmed 20 minutes after it started, the loader goes back to the version
// it replaced. A version that fails to come up for a reason outside it exits
// with its own code (69: an endpoint it could not reach, a download) and is
// started again later instead. A sealed that exits on its own is restarted,
// a bounded number of times; one that exits because its owner asked for a
// restart (code 76) is started again at once. Without the layered flow the
// loader runs /bootstrap only and exits when it exits, as when sealed is
// PID 1.
//
// The environment, container key included, goes to sealed unchanged but for
// SEALED_HASH (the hash the loader checked), SEALED_TRIAL and
// SEALED_INSTEAD_OF: sealed reads and scrubs it exactly as it does when it is
// PID 1 itself, and the loader keeps it for the next sealed it starts. Like
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

// expectedSealedHash is the lowercase hex sha256 of the image's own sealed
// binary, set at build time. Empty means the build did not set it, and the
// loader then runs nothing.
var expectedSealedHash = ""

// sealedPath is where the image puts its sealed binary.
const sealedPath = "/bootstrap"

// loaderState is the loader's state directory (state.go).
const loaderState = "/var/lib/loader"

func main() {
	harden()
	if err := verifyFile(sealedPath, expectedSealedHash); err != nil {
		logf("FAIL %v", err)
		os.Exit(1)
	}
	logf("OK   %s matches the sealed hash built into the loader (%s)", sealedPath, expectedSealedHash)

	// Registered before sealed starts, so its exit cannot slip past.
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGCHLD, syscall.SIGUSR1)

	state := stateDir(loaderState)
	if err := state.prepare(); err != nil {
		// Without its state directory the loader cannot switch versions; it
		// still runs the image's sealed.
		logf("WARN %s: %v; running %s only", loaderState, err, sealedPath)
		state = ""
	}
	s := &supervisor{
		builtin:          version{hash: expectedSealedHash, path: sealedPath},
		state:            state,
		allow:            newAllowlist(os.Getenv(chainRPCEnv), os.Getenv(contractEnv)),
		stdout:           os.Stdout,
		stderr:           os.Stderr,
		reapAll:          os.Getpid() == 1,
		sigs:             sigs,
		stopGrace:        stopGrace,
		poll:             time.Second,
		backoff:          restartBackoff,
		window:           restartWindow,
		trialLimit:       trialLimit,
		transientLimit:   transientLimit,
		transientBackoff: transientRetryBackoff,
		logf:             logf,
	}
	os.Exit(s.run())
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "loader: "+format+"\n", a...)
}
