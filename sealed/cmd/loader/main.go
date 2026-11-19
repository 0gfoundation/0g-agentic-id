// Command loader is PID 1 in the layered 0g-harness image (sealed/LAYERS.md).
// It runs sealed as its child, after checking the program against its hash,
// forwards stop signals to it, reaps orphaned processes, and restarts it.
//
// The image holds no sealed of its own: base and this loader are all the
// image hash covers. Every sealed version comes from the trust registry's
// sealed list on chain (allowlist.go) and from the official artifacts
// release (fetch.go): the loader runs a version only on the chain's explicit
// "listed", and only once its program hashes to that version's name. The
// check comes before exec, because sealed obtains the agent identity key once
// it runs: a check made afterwards would be a claim by the code being
// checked.
//
// At each start the loader runs the version it ran last while the chain
// lists it and it did not fail here, else the one that replaced, else the
// newest listed one (supervise.go choose), downloading it when it is not
// here. When the list cannot be read, or lists nothing this container can
// run, nothing runs: the loader reads the list again after a wait. sealed
// switches versions in place: it stages the version to run (the owner's
// pick, or the newest listed one when its own is delisted) in the loader's
// state directory, which only root can enter, and asks for the switch
// (SIGUSR1). The loader hashes the staged program again, checks the list
// itself, stops the running sealed, ends whatever it left behind, and starts
// the new one. A version that has not come up in this container runs on
// trial: if it exits before it confirms it came up, or has not confirmed 20
// minutes after it started, it does not run here again and the loader takes
// the next version. A version that fails to come up for a reason outside it
// exits with its own code (69: an endpoint it could not reach, a download)
// and is started again later instead. A sealed that came up and exits on its
// own is restarted, a bounded number of times; one that exits because its
// owner asked for a restart (code 76) is started again at once.
//
// The environment, container key included, goes to sealed unchanged but for
// SEALED_HASH (the hash the loader checked) and SEALED_TRIAL: sealed reads
// and scrubs it exactly as it does when it is PID 1 itself, and the loader
// keeps it for the next sealed it starts. Like sealed, the loader is root,
// non-dumpable and sets no_new_privs, so another uid cannot read it from
// /proc/1/environ.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// loaderState is the loader's state directory (state.go).
const loaderState = "/var/lib/loader"

func main() {
	harden()

	// Registered before sealed starts, so its exit cannot slip past.
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGCHLD, syscall.SIGUSR1)

	state := stateDir(loaderState)
	if err := state.prepare(); err != nil {
		logf("FAIL %s: %v; no sealed version can be kept or run without it", loaderState, err)
		os.Exit(1)
	}
	s := &supervisor{
		state:            state,
		allow:            newAllowlist(os.Getenv(chainRPCEnv), os.Getenv(contractEnv)),
		artifacts:        artifactsURL,
		http:             newArtifactClient(),
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
