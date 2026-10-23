package framework

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"seal-verify/internal/privsep"
)

// StateDir holds sealed's own per-container state: bookkeeping an adapter
// keeps about its framework (the openclaw applied-overlay record, the
// conversation identities), the framework processes' logs (log/) and
// download scratch space (tmp/). It is root-owned 0700 and lives outside
// every tree handed to the agent user, so nothing in it is agent-writable
// and none of it is chain-tracked; it lives and dies with the container.
//
// A var so tests can redirect it into t.TempDir(). Production code never
// reassigns it.
var StateDir = "/var/lib/sealed"

// StatePath is the path of one state file.
func StatePath(name string) string { return filepath.Join(StateDir, name) }

// StateSubdir creates (if needed) and returns a directory under StateDir.
// An empty name is StateDir itself.
func StateSubdir(name string) (string, error) {
	dir := StateDir
	if name != "" {
		dir = filepath.Join(StateDir, name)
	}
	if err := privsep.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// ReadState reads one state file. A missing file satisfies
// errors.Is(err, fs.ErrNotExist).
func ReadState(name string) ([]byte, error) {
	return privsep.ReadFile(StatePath(name), privsep.LimitConfig)
}

// WriteState atomically replaces one state file (mode 0600).
func WriteState(name string, data []byte) error {
	if _, err := StateSubdir(""); err != nil {
		return err
	}
	return privsep.WriteFile(StatePath(name), data, 0o600)
}

// RemoveState removes one state file; a missing file is not an error.
func RemoveState(name string) error {
	if err := privsep.Remove(StatePath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// LogPath is where a framework process's stdout/stderr go (OpenLog) and
// what SubprocessLogPath reports for /log/agent.
func LogPath(name string) string { return filepath.Join(StateDir, "log", name+".log") }

// OpenLog truncates and opens LogPath(name) for the framework process's
// output. The log directory is root-only, and the file is opened without
// following a link at its name.
func OpenLog(name string) (*os.File, error) {
	if _, err := StateSubdir("log"); err != nil {
		return nil, err
	}
	return os.OpenFile(LogPath(name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
}
