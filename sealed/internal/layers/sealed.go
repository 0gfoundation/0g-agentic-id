package layers

// The hand-over between sealed and the loader (cmd/loader), through files in
// LoaderDir, which only root can enter:
//
//	sealed/<hash>  a sealed program staged for the loader: written here only
//	               once it hashed to its name, and hashed again by the loader
//	               before it runs it
//	request        the hash sealed asks the loader to switch to; SIGUSR1 to
//	               the loader (sealed's parent) says it is there
//	confirmed      the hash of the version that came up; a version the loader
//	               started on trial is kept only once this names it
//	layered        written once the attestor declared the layered flow: from
//	               then on the loader restarts a sealed that exits on its own
//	               instead of exiting with it
//	failed         the versions the loader went back from, one hash per line;
//	               sealed does not switch to them again
//
// Keep these names, the environment variables and TrialFailedExit in step
// with cmd/loader.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"seal-verify/internal/privsep"
)

// LoaderDir is the loader's state directory. A var so tests can redirect it;
// production code never reassigns it.
var LoaderDir = "/var/lib/loader"

const (
	// SealedHashEnv is set by the loader for the sealed it starts: the
	// sha256 it verified, 64 lowercase hex.
	SealedHashEnv = "SEALED_HASH"
	// TrialEnv is set ("1") by the loader when it starts a version it
	// switched to and has not seen confirmed.
	TrialEnv = "SEALED_TRIAL"
	// TrialFailedExit is the exit code of a sealed on trial whose boot
	// failed: the loader then goes back to the version it switched from.
	TrialFailedExit = 75
)

// StagedSealedPath is where a staged sealed program with this hash lives.
func StagedSealedPath(hash string) string { return filepath.Join(LoaderDir, "sealed", hash) }

// StageSealed writes the sealed program read from r to StagedSealedPath(hash),
// executable by root only. r must fail at its end unless the program hashes
// to hash (FetchArtifact, VerifyingReader); on any error nothing is left at
// that path.
func StageSealed(r io.Reader, hash string) error {
	if err := privsep.MkdirAll(filepath.Join(LoaderDir, "sealed"), 0o700); err != nil {
		return err
	}
	if _, err := privsep.WriteFileFrom(StagedSealedPath(hash), r, 0o500); err != nil {
		return fmt.Errorf("stage sealed %s: %w", hash, err)
	}
	return nil
}

// RequestSwitch asks the loader to switch to the staged version hash. The
// loader checks the staged program's hash once more, stops this sealed
// (SIGTERM, the usual stop) and starts the new one on trial.
func RequestSwitch(hash string) error {
	if err := privsep.WriteFile(filepath.Join(LoaderDir, "request"), []byte(hash), 0o600); err != nil {
		return err
	}
	return signalLoader()
}

// signalLoader tells the loader, sealed's parent, that a request is there.
// A var so tests do not signal the process that runs them.
var signalLoader = func() error {
	if os.Getpid() == 1 {
		return fmt.Errorf("sealed is PID 1: there is no loader to switch versions")
	}
	return syscall.Kill(os.Getppid(), syscall.SIGUSR1)
}

// SealedFailed reports whether the loader went back from version hash in
// this container.
func SealedFailed(hash string) bool {
	b, err := privsep.ReadFile(filepath.Join(LoaderDir, "failed"), 1<<20)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == hash {
			return true
		}
	}
	return false
}

// Confirm tells the loader that the version hash came up.
func Confirm(hash string) error {
	return privsep.WriteFile(filepath.Join(LoaderDir, "confirmed"), []byte(hash), 0o600)
}

// MarkLayered tells the loader the attestor runs the layered flow.
func MarkLayered() error {
	if err := privsep.MkdirAll(LoaderDir, 0o700); err != nil {
		return err
	}
	return privsep.WriteFile(filepath.Join(LoaderDir, "layered"), []byte("1"), 0o600)
}
