package main

// The loader's state directory, shared with sealed (sealed/internal/layers,
// sealed.go, which writes the same names; keep the two in step):
//
//	sealed/<hash>  sealed programs, downloaded here (fetch.go) or staged by
//	               sealed for a switch; each is hashed again before it runs
//	request        the version sealed asked to switch to (SIGUSR1 says so)
//	confirmed      the version that came up, written by sealed
//	current        the version to run, written here
//	previous       the version current replaced, written here
//	failed         versions that did not come up here, one per line
//	mismatched     versions whose download did not hash to its name, one per
//	               line; not downloaded again
//
// sealed also writes `layered` there, for the loaders of earlier images; this
// loader does not read it.
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

// staged is where version hash's program is kept.
func (d stateDir) staged(hash string) string { return filepath.Join(string(d), "sealed", hash) }

// holds reports whether the list file name holds hash.
func (d stateDir) holds(name, hash string) bool {
	for _, line := range strings.Split(d.read(name), "\n") {
		if strings.TrimSpace(line) == hash {
			return true
		}
	}
	return false
}

// add appends hash to the list file name.
func (d stateDir) add(name, hash string) error {
	if d.holds(name, hash) {
		return nil
	}
	var b bytes.Buffer
	if prev := d.read(name); prev != "" {
		b.WriteString(prev + "\n")
	}
	b.WriteString(hash + "\n")
	return d.write(name, b.String())
}

// failed reports whether version hash did not come up here.
func (d stateDir) failed(hash string) bool { return d.holds("failed", hash) }

// markFailed records that version hash did not come up here.
func (d stateDir) markFailed(hash string) error { return d.add("failed", hash) }

// mismatched reports whether a download of version hash did not hash to its
// name here.
func (d stateDir) mismatched(hash string) bool { return d.holds("mismatched", hash) }

// markMismatched records that a download of version hash did not hash to its
// name.
func (d stateDir) markMismatched(hash string) error { return d.add("mismatched", hash) }
