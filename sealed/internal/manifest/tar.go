package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
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
//   - Only directories and regular files are packed: symlinks (target may
//     be host-specific), FIFOs, sockets and devices are skipped, as is any
//     file the privsep read rules refuse (a multiply-linked file owned by
//     someone else). dir is typically agent-writable, so the walk never
//     follows a link and never opens a non-regular file (internal/privsep).
//   - Files are streamed into the archive whatever their size, as earlier
//     packers did. Only the archive's total uncompressed size is bounded,
//     by maxPackTotal — what sealed can hold while it commits the entry,
//     well under the bound UnpackDir applies (maxUnpackTotal), so whatever
//     is packed restores. Over it PackDir fails with privsep.ErrTooLarge,
//     which producers turn into a held entry (Held, DirEntryOf), so the
//     entry keeps its committed version rather than being committed
//     without some of its files.
//   - Memory is the compressed output plus a copy buffer; PackDirDigest,
//     which the watcher uses on every pass, holds only the copy buffer
//     and the compressor's state.
//   - The embedded gzip header has zero mtime / no name / no comment.
//
// Determinism is conditional on the Go standard library version: a Go
// update may alter compress/flate output for the same input. That manifests
// as a one-time hash change after a Go upgrade; the watcher will see drift
// once and re-push, which is acceptable churn.
func PackDir(dir string) ([]byte, error) {
	var buf bytes.Buffer
	if err := packDirTo(dir, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PackDirDigest returns HashHex and the length of the archive PackDir(dir)
// returns, without holding the archive: it is streamed into the hash. The
// watcher packs every directory entry on every pass to see whether it
// changed; only an upload needs the bytes.
func PackDirDigest(dir string) (hash string, size int, err error) {
	h := sha256.New()
	cw := &countingWriter{w: h}
	if err := packDirTo(dir, cw); err != nil {
		return "", 0, err
	}
	return "0x" + hex.EncodeToString(h.Sum(nil)), int(cw.n), nil
}

// countingWriter counts what it passes on.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// packDirTo writes the archive PackDir describes to out.
func packDirTo(dir string, out io.Writer) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("manifest: walk %s: %w", dir, err)
	}
	items, err := walkSorted(abs)
	if err != nil {
		return err
	}

	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("manifest: gzip writer: %w", err)
	}
	// Zero gzip header metadata for determinism.
	gz.ModTime = time.Time{}
	gz.Name = ""
	gz.Comment = ""
	gz.OS = 255 // "unknown" — avoids OS-specific default

	tw := tar.NewWriter(gz)

	budget := maxPackTotal
	for _, it := range items {
		hdr := &tar.Header{
			Name:    it.rel,
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
		if it.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
			hdr.Name += "/"
			if err := tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("manifest: write header %s: %w", it.rel, err)
			}
			continue
		}
		n, err := packFile(tw, hdr, abs+"/"+it.rel, budget)
		if err != nil {
			return err
		}
		budget -= n
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("manifest: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("manifest: close gzip: %w", err)
	}
	return nil
}

// packFile streams the regular file full into tw under hdr, opened once
// (privsep.Open: no link followed, regular files only). The header size is
// the size of the file as opened; a file that shrinks while it is copied
// fails the pack (the next pass packs it again) rather than be padded. A
// file removed or swapped since the walk is left out (n == 0, nil). budget
// is what the archive may still hold, uncompressed.
func packFile(tw *tar.Writer, hdr *tar.Header, full string, budget int64) (int64, error) {
	f, err := privsep.Open(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || privsep.Refused(full, err) {
			return 0, nil // removed or swapped meanwhile
		}
		return 0, fmt.Errorf("manifest: open %s: %w", full, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("manifest: stat %s: %w", full, err)
	}
	size := fi.Size()
	if size > budget {
		return 0, fmt.Errorf("manifest: pack %s: the archive would hold more than %d bytes: %w", full, maxPackTotal, privsep.ErrTooLarge)
	}
	hdr.Typeflag = tar.TypeReg
	hdr.Mode = 0o644
	hdr.Size = size
	if err := tw.WriteHeader(hdr); err != nil {
		return 0, fmt.Errorf("manifest: write header %s: %w", hdr.Name, err)
	}
	n, err := io.CopyN(tw, f, size)
	if err == io.EOF {
		return n, fmt.Errorf("manifest: %s shrank while it was being packed", full)
	}
	if err != nil {
		return n, fmt.Errorf("manifest: copy %s: %w", full, err)
	}
	return n, nil
}

// maxUnpackTotal bounds the total uncompressed size of one archive
// UnpackDir extracts. Generous on purpose: it guards against a
// decompression bomb, not against large files — any archive an earlier
// sealed committed (whose packer had no size limit, or a 4 GiB one) must
// still restore. A var so tests can lower it.
var maxUnpackTotal int64 = 4 << 30

// maxPackTotal bounds the total uncompressed size of one archive PackDir
// produces: what sealed (root, PID 1) can afford to hold while it commits a
// directory entry. The archive is held in memory (for incompressible
// content, about as large as the files), and committing it holds it again,
// encrypted (LoadEntry, dataplane.Encrypt, Upload), so the bound keeps
// sealed's peak to a small multiple of it however large the agent makes a
// tracked directory. A directory restored from a larger archive an earlier
// sealed committed is held at that committed version until it is back
// under the bound. A var so tests can lower it.
var maxPackTotal int64 = 256 << 20

// ArchiveLimit is the largest uncompressed size of one directory entry's
// archive that is packed (PackDir); the agent doc states it.
func ArchiveLimit() int64 { return maxPackTotal }

// UnpackDir extracts a tar.gz produced by PackDir into dst. dst is created
// if missing. Existing files at the same path are replaced; existing extra
// files in dst are NOT removed (caller decides cleanup policy).
//
// Refuses entries whose path escapes dst (ZipSlip defence) and rejects
// unexpected typeflags (only regular files and directories). Directories
// are created and files written through internal/privsep, so a link
// anywhere on the way (dst's parents included) is refused rather than
// followed, and a file is always written as a fresh regular file. Members
// are streamed to disk, whatever their size; only the archive's total
// decompressed size is bounded (maxUnpackTotal).
func UnpackDir(tarball []byte, dst string) error {
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return fmt.Errorf("manifest: abs dst: %w", err)
	}
	if err := privsep.MkdirAll(dstAbs, 0o755); err != nil {
		return fmt.Errorf("manifest: mkdir %s: %w", dstAbs, err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return fmt.Errorf("manifest: gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	remaining := maxUnpackTotal

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
			if err := privsep.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("manifest: mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if target == dstAbs {
				return fmt.Errorf("manifest: file entry names dst itself: %q", hdr.Name)
			}
			if hdr.Size > remaining {
				return fmt.Errorf("manifest: archive decompresses to more than %d bytes", maxUnpackTotal)
			}
			if err := privsep.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("manifest: mkdir parent of %s: %w", target, err)
			}
			n, err := privsep.WriteFileFrom(target, io.LimitReader(tr, remaining), 0o644)
			if err != nil {
				return fmt.Errorf("manifest: write %s: %w", target, err)
			}
			remaining -= n
		default:
			return fmt.Errorf("manifest: unsupported tar typeflag %d in %q", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

// packItem is one entry PackDir writes: a directory or a regular file,
// by its path relative to the packed directory. A file's bytes are read
// only when it is written.
type packItem struct {
	rel string // slash-separated, relative to the packed dir
	dir bool
}

// maxPackDepth bounds the walk; deeper subtrees are skipped with a log line
// (once per path per process).
const maxPackDepth = 128

// walkSorted returns every directory and regular file under abs (relative
// paths, lex order), excluding abs itself.
func walkSorted(abs string) ([]packItem, error) {
	var items []packItem
	var walk func(full, rel string, depth int) error
	walk = func(full, rel string, depth int) error {
		ents, err := privsep.ReadDir(full)
		if err != nil {
			return err
		}
		for _, e := range ents {
			childFull := full + "/" + e.Name()
			childRel := e.Name()
			if rel != "" {
				childRel = rel + "/" + e.Name()
			}
			switch {
			case e.IsDir():
				if depth+1 >= maxPackDepth {
					logger.Once("manifest.depth:"+childFull, "manifest: %q is deeper than %d levels; not packed", childFull, maxPackDepth)
					continue
				}
				items = append(items, packItem{rel: childRel, dir: true})
				if err := walk(childFull, childRel, depth+1); err != nil {
					if errors.Is(err, fs.ErrNotExist) || privsep.Refused(childFull, err) {
						continue // removed or swapped meanwhile
					}
					return err
				}
			case e.IsRegular():
				items = append(items, packItem{rel: childRel})
			}
		}
		return nil
	}
	if err := walk(abs, "", 0); err != nil {
		return nil, fmt.Errorf("manifest: walk %s: %w", abs, err)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].rel < items[j].rel })
	return items, nil
}
