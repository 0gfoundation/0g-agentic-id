package layers

// Harness official version packages (sealed/LAYERS.md §5). A package is the
// gzip'd tar of an installed 0g-harness package directory (its source,
// package.json, lockfile and node_modules built for base's node, native
// modules included), named by the sha256 of the .tgz. Each one is unpacked
// into its own directory under PackagesDir, owned by root and read-only to
// everyone else: the harness runs from there as the agent user, who can read
// and run it but not change it. base ships one, which PackagesDir/base
// names; the others are fetched by hash and unpacked by InstallHarness.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// PackagesDir holds the unpacked packages, one directory per hash. A var so
// tests can redirect it; production code never reassigns it.
var PackagesDir = "/opt/0g-harness"

// baseFile, under PackagesDir, names the package base ships.
const baseFile = "base"

// selectionFile, under framework.StateDir, records which package runs.
const selectionFile = "harness.json"

// Limits of one package's contents.
const (
	maxPackageEntries = 200_000
	maxPackageBytes   = 4 << 30
)

// BaseHarness is the hash of the package base ships.
func BaseHarness() (string, error) {
	b, err := privsep.ReadFile(filepath.Join(PackagesDir, baseFile), 4<<10)
	if err != nil {
		return "", err
	}
	h, ok := ParseHash(string(b))
	if !ok {
		return "", fmt.Errorf("%s does not hold a sha256", filepath.Join(PackagesDir, baseFile))
	}
	return h, nil
}

// HarnessDir is where the package with this hash is unpacked.
func HarnessDir(hash string) string { return filepath.Join(PackagesDir, hash) }

// HarnessInstalled reports whether the package with this hash is unpacked.
func HarnessInstalled(hash string) bool {
	fi, err := privsep.Lstat(HarnessDir(hash))
	return err == nil && fi.IsDir()
}

// HarnessSelection is the record of which package runs: Current, and the
// one it replaced, which a failed switch goes back to.
type HarnessSelection struct {
	Current  string `json:"current"`
	Previous string `json:"previous,omitempty"`
}

// LoadHarnessSelection reads the record; the zero value when there is none
// or it does not parse.
func LoadHarnessSelection() HarnessSelection {
	var s HarnessSelection
	b, err := framework.ReadState(selectionFile)
	if err != nil || json.Unmarshal(b, &s) != nil {
		return HarnessSelection{}
	}
	if h, ok := ParseHash(s.Current); ok {
		s.Current = h
	} else {
		s.Current = ""
	}
	if h, ok := ParseHash(s.Previous); ok {
		s.Previous = h
	} else {
		s.Previous = ""
	}
	return s
}

// SaveHarnessSelection writes the record.
func SaveHarnessSelection(s HarnessSelection) error {
	b, err := json.Marshal(&s)
	if err != nil {
		return err
	}
	return framework.WriteState(selectionFile, b)
}

// failedDir, under framework.StateDir, holds one empty file per package that
// did not come up in this container.
const failedDir = "harness-failed"

// MarkHarnessFailed records that package hash did not come up here.
func MarkHarnessFailed(hash string) {
	dir, err := framework.StateSubdir(failedDir)
	if err == nil {
		err = privsep.WriteFile(filepath.Join(dir, hash), nil, 0o600)
	}
	if err != nil {
		logger.Logf("layers: record that harness %s failed: %v", hash, err)
	}
}

// HarnessFailed reports whether package hash did not come up here before.
func HarnessFailed(hash string) bool {
	_, err := privsep.Lstat(filepath.Join(framework.StateDir, failedDir, hash))
	return err == nil
}

// InstallHarness unpacks the package read from r into HarnessDir(hash). r
// must fail at its end unless the package hashes to hash (FetchArtifact,
// VerifyingReader): the package is first written whole to a root-only
// temporary file, so one that fails that check, or fails to download, is
// never unpacked. The unpacked tree is moved into place only once complete.
// A package already in place is left as it is.
func InstallHarness(r io.Reader, hash string) error {
	if HarnessInstalled(hash) {
		return nil
	}
	tmp, err := privsep.TempDir("harness-")
	if err != nil {
		return err
	}
	defer privsep.RemoveAll(tmp)
	tgz := filepath.Join(tmp, "package.tgz")
	if _, err := privsep.WriteFileFrom(tgz, r, 0o600); err != nil {
		return fmt.Errorf("fetch the package: %w", err)
	}
	f, err := privsep.Open(tgz)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := privsep.MkdirAll(PackagesDir, 0o755); err != nil {
		return err
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	stage := filepath.Join(PackagesDir, ".install-"+hash+"-"+hex.EncodeToString(suffix[:]))
	if err := unpackPackage(f, stage); err != nil {
		privsep.RemoveAll(stage)
		return fmt.Errorf("unpack the package: %w", err)
	}
	if err := privsep.RenameNoReplace(stage, HarnessDir(hash)); err != nil {
		privsep.RemoveAll(stage)
		if errors.Is(err, fs.ErrExist) && HarnessInstalled(hash) {
			return nil
		}
		return err
	}
	return nil
}

// unpackPackage extracts a gzip'd tar into dir, which it creates. Only
// directories, regular files and symbolic links whose target stays inside
// dir are accepted; any other entry, a name that leaves dir, or contents
// beyond the limits fail the whole package. Directories are 0755, files
// 0755 when the archive marks them executable and 0644 otherwise, all owned
// by root (the owner of PackagesDir).
func unpackPackage(r io.Reader, dir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := mkdir(dir); err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	var entries, total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if entries++; entries > maxPackageEntries {
			return fmt.Errorf("more than %d entries", maxPackageEntries)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if !fs.ValidPath(name) {
			return fmt.Errorf("entry %q leaves the package", h.Name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := privsep.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := mkdir(dst); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += h.Size; total > maxPackageBytes {
				return fmt.Errorf("more than %d bytes", int64(maxPackageBytes))
			}
			mode := fs.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			if _, err := privsep.WriteFileFrom(dst, io.LimitReader(tr, h.Size), mode); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if path.IsAbs(h.Linkname) || !fs.ValidPath(path.Join(path.Dir(name), h.Linkname)) {
				return fmt.Errorf("link %q -> %q leaves the package", h.Name, h.Linkname)
			}
			if err := privsep.Symlink(h.Linkname, dst); err != nil {
				return err
			}
		default:
			return fmt.Errorf("entry %q is not a directory, regular file or link (type %q)", h.Name, h.Typeflag)
		}
	}
}

// mkdir makes dir a 0755 directory whatever the umask.
func mkdir(dir string) error {
	if err := privsep.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return privsep.Chmod(dir, 0o755)
}
