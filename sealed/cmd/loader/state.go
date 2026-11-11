package main

// The loader's state directory, shared with sealed (sealed/internal/layers,
// sealed.go, which writes the same names; keep the two in step):
//
//	sealed/<hash>  sealed programs sealed staged; each is hashed again here
//	               before it runs
//	request        the version sealed asked to switch to (SIGUSR1 says so)
//	confirmed      the version that came up, written by sealed
//	layered        written by sealed once the attestor runs the layered flow
//	current        the version to run, written here
//	previous       the version current replaced, written here
//	failed         versions the loader went back from, one per line
//
// The directory is root's, mode 0700: only the loader and sealed, both root,
// can enter it.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// stateDir is the loader's state directory.
type stateDir string

// prepare creates the directory, root-only.
func (d stateDir) prepare() error {
	if err := os.MkdirAll(string(d), 0o700); err != nil {
		return err
	}
	return os.Chmod(string(d), 0o700)
}

// read returns one file's content, trimmed; "" when it is missing.
func (d stateDir) read(name string) string {
	b, err := os.ReadFile(filepath.Join(string(d), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// write replaces one file: written next to it, then renamed over it.
func (d stateDir) write(name, content string) error {
	p := filepath.Join(string(d), name)
	if err := os.WriteFile(p+".new", []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(p+".new", p)
}

// hash reads a file that names a version: 64 lowercase hex, or "".
func (d stateDir) hash(name string) string {
	h := d.read(name)
	if b, err := hex.DecodeString(h); err != nil || len(b) != 32 || hex.EncodeToString(b) != h {
		return ""
	}
	return h
}

// staged is where sealed staged version hash.
func (d stateDir) staged(hash string) string { return filepath.Join(string(d), "sealed", hash) }

// failed reports whether the loader went back from version hash.
func (d stateDir) failed(hash string) bool {
	for _, line := range strings.Split(d.read("failed"), "\n") {
		if strings.TrimSpace(line) == hash {
			return true
		}
	}
	return false
}

// markFailed adds version hash to failed.
func (d stateDir) markFailed(hash string) error {
	if d.failed(hash) {
		return nil
	}
	var b bytes.Buffer
	if prev := d.read("failed"); prev != "" {
		b.WriteString(prev + "\n")
	}
	b.WriteString(hash + "\n")
	return d.write("failed", b.String())
}

// layered reports whether sealed said the attestor runs the layered flow.
func (d stateDir) layered() bool { return d.read("layered") != "" }
