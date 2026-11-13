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
//	current        the version the loader runs, previous the one it
//	               replaced: written by the loader, read here
//
// Keep these names, the environment variables and the exit codes in step
// with cmd/loader (supervise.go, state.go).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"seal-verify/internal/logger"
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
	// InsteadOfEnv is set by the loader when it runs the image's own sealed
	// in place of the version it records, because the sealed list could not
	// be read: that version's hash. Once the list confirms it, sealed asks
	// to go back to it.
	InsteadOfEnv = "SEALED_INSTEAD_OF"
)

// The exit codes sealed tells the loader something with. Any other exit of a
// version on trial before it confirms reads as that version failing.
const (
	// TrialFailedExit is the exit code of a sealed on trial whose boot
	// failed: the loader then goes back to the version it switched from.
	TrialFailedExit = 75
	// TrialTransientExit is the exit code of a boot that failed for a reason
	// outside this version (an endpoint it could not reach, a download): the
	// loader starts the same version again after a wait, and does not count
	// it against it.
	TrialTransientExit = 69
	// RestartRequestedExit is the exit code of a sealed its owner asked to
	// restart: the loader starts it again at once.
	RestartRequestedExit = 76
)

// StagedSealedPath is where a staged sealed program with this hash lives.
func StagedSealedPath(hash string) string { return filepath.Join(LoaderDir, "sealed", hash) }

// SealedStaged reports whether a program hashing to hash is staged already,
// so a switch to it needs no download (the loader hashes it once more).
func SealedStaged(hash string) bool {
	f, err := privsep.Open(StagedSealedPath(hash))
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxArtifactBytes+1)); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == hash
}

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
		// LEGACY(v1): sealed as PID 1, in an image without the loader.
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
//
// LEGACY(pre-1.4.0): the loader needs telling only because an attestor on a
// chain whose AgenticID names no trust registry runs no layered flow, and the
// loader then stops with sealed. Once every environment is on AgenticID
// 1.4.0 the loader can always restart sealed.
func MarkLayered() error {
	if err := privsep.MkdirAll(LoaderDir, 0o700); err != nil {
		return err
	}
	return privsep.WriteFile(filepath.Join(LoaderDir, "layered"), []byte("1"), 0o600)
}

// Layered reports whether a sealed in this container has told the loader the
// attestor runs the layered flow: from then on the loader starts sealed again
// when it exits.
func Layered() bool {
	_, err := privsep.Lstat(filepath.Join(LoaderDir, "layered"))
	return err == nil
}

// readHash reads a loader state file that names a version: 64 lowercase
// hex, or "".
func readHash(name string) string {
	b, err := privsep.ReadFile(filepath.Join(LoaderDir, name), 4<<10)
	if err != nil {
		return ""
	}
	h, ok := ParseHash(string(b))
	if !ok || h != strings.TrimSpace(string(b)) {
		return ""
	}
	return h
}

// CleanCutOffStaging removes the partial files a staging a stop or a crash
// cut off left in the loader's directory. Only while nothing is staged (at
// boot).
func CleanCutOffStaging() {
	dir := filepath.Join(LoaderDir, "sealed")
	entries, err := privsep.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if _, ok := ParseHash(e.Name()); ok && e.Name() == strings.ToLower(e.Name()) {
			continue
		}
		if err := privsep.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			logger.Logf("layers: remove %s: %v", filepath.Join(dir, e.Name()), err)
		}
	}
}

// PruneStaged removes the staged sealed programs no version the loader may
// run names: every one but keep and those its state names (current,
// previous, confirmed and a pending request), and the files a download cut
// off left behind. Call it only while no switch is asked for.
func PruneStaged(keep ...string) {
	dir := filepath.Join(LoaderDir, "sealed")
	entries, err := privsep.ReadDir(dir)
	if err != nil {
		return
	}
	kept := map[string]bool{}
	for _, h := range keep {
		if p, ok := ParseHash(h); ok {
			kept[p] = true
		}
	}
	for _, name := range []string{"current", "previous", "confirmed", "request"} {
		if h := readHash(name); h != "" {
			kept[h] = true
		}
	}
	for _, e := range entries {
		if kept[e.Name()] {
			continue
		}
		if err := privsep.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			logger.Logf("layers: remove the staged sealed %s: %v", e.Name(), err)
			continue
		}
		logger.Logf("layers: removed the staged sealed %s, which nothing here runs", e.Name())
	}
}
