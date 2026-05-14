package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PackDir reads dir recursively and returns a deterministic gzip-compressed
// tar of its contents (not the directory itself — the tar contains entries
// like "subdir/file", not "dir/subdir/file").
//
// Guarantees:
//   - Same dir contents → byte-identical output, regardless of filesystem
//     iteration order, mtime, uid/gid, or umask differences across hosts.
//   - Entries appear in lexicographic path order.
//   - All tar header timestamps and ownership fields are zeroed.
//   - File modes are normalised: directories 0755, files 0644.
//   - Symlinks are skipped (target may be host-specific).
//   - The embedded gzip header has zero mtime / no name / no comment.
//
// Determinism is conditional on the Go standard library version: a Go
// update may alter compress/flate output for the same input. That manifests
// as a one-time hash change after a Go upgrade; the watcher will see drift
// once and re-push, which is acceptable churn.
func PackDir(dir string) ([]byte, error) {
	paths, err := walkSorted(dir)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("manifest: gzip writer: %w", err)
	}
	// Zero gzip header metadata for determinism.
	gz.ModTime = time.Time{}
	gz.Name = ""
	gz.Comment = ""
	gz.OS = 255 // "unknown" — avoids OS-specific default

	tw := tar.NewWriter(gz)

	for _, rel := range paths {
		full := filepath.Join(dir, rel)
		info, err := os.Lstat(full)
		if err != nil {
			return nil, fmt.Errorf("manifest: stat %s: %w", full, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		hdr := &tar.Header{
			Name:    filepath.ToSlash(rel),
			ModTime: time.Time{},
			Uname:   "",
			Gname:   "",
			Uid:     0,
			Gid:     0,
			// PAX (not USTAR) — USTAR can't encode non-ASCII paths or
			// names longer than 100 bytes. PAX writes a synthetic
			// extended header for those cases; the extended header
			// itself is deterministic given the same input.
			Format: tar.FormatPAX,
		}
		if info.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
			hdr.Name += "/"
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Mode = 0o644
			hdr.Size = info.Size()
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("manifest: write header %s: %w", rel, err)
		}
		if !info.IsDir() {
			f, err := os.Open(full)
			if err != nil {
				return nil, fmt.Errorf("manifest: open %s: %w", full, err)
			}
			_, err = io.Copy(tw, f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("manifest: copy %s: %w", rel, err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("manifest: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("manifest: close gzip: %w", err)
	}
	return buf.Bytes(), nil
}

// UnpackDir extracts a tar.gz produced by PackDir into dst. dst is created
// if missing. Existing files at the same path are overwritten; existing
// extra files in dst are NOT removed (caller decides cleanup policy).
//
// Refuses entries whose path escapes dst (ZipSlip defence) and rejects
// unexpected typeflags (only regular files and directories).
func UnpackDir(tarball []byte, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("manifest: mkdir %s: %w", dst, err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return fmt.Errorf("manifest: gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return fmt.Errorf("manifest: abs dst: %w", err)
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("manifest: tar next: %w", err)
		}

		clean := filepath.Clean(filepath.FromSlash(hdr.Name))
		// IsAbs is an explicit early reject; the prefix check below would
		// catch it anyway after Join (since Join("/dst", "/x") = "/x"),
		// but failing loudly here makes the intent clear.
		if filepath.IsAbs(clean) {
			return fmt.Errorf("manifest: rejected absolute entry path: %q", hdr.Name)
		}
		target := filepath.Join(dstAbs, clean)
		if !strings.HasPrefix(target, dstAbs+string(filepath.Separator)) && target != dstAbs {
			return fmt.Errorf("manifest: entry escapes dst: %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("manifest: mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("manifest: mkdir parent of %s: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return fmt.Errorf("manifest: open %s for write: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("manifest: write %s: %w", target, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("manifest: close %s: %w", target, err)
			}
		default:
			return fmt.Errorf("manifest: unsupported tar typeflag %d in %q", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

// walkSorted returns all entries under dir (relative paths, lex order),
// excluding dir itself.
func walkSorted(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		paths = append(paths, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("manifest: walk %s: %w", dir, err)
	}
	sort.Strings(paths)
	return paths, nil
}
