package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

func TestValidEntryPath(t *testing.T) {
	for _, bad := range []string{"a/b", "../x", "..", ".", "", "/", "x\x00y", "a/b/", "../", "/abs", "./", "..//", "caf\xe9.md", "dir\xff/"} {
		if ValidEntryPath(bad) == nil {
			t.Errorf("ValidEntryPath accepted %q", bad)
		}
	}
	// Any UTF-8 name a directory listing can return is a valid entry path;
	// a backslash is an ordinary file-name byte on Linux.
	for _, good := range []string{"x.md", "slug/", ".h.md", "日本.md", "a..b", "a\\b", "notes\\todo.md", "dir\\x/", "...", " "} {
		if err := ValidEntryPath(good); err != nil {
			t.Errorf("ValidEntryPath refused %q: %v", good, err)
		}
	}
	if !Carries("/w", "a\\b.md") || Carries("/w", "..") || Carries("/w", "caf\xe9.md") {
		t.Fatal("Carries disagrees with ValidEntryPath")
	}
}

// Unmarshal drops an individual invalid entry (which a manifest committed
// by an older sealed, or crafted, may hold) and keeps every other entry,
// instead of failing the whole manifest.
func TestUnmarshalDropsInvalidEntriesOnly(t *testing.T) {
	m := New()
	m.Entries = append(m.Entries,
		Entry{Path: "good.md", Kind: EntryFile},
		Entry{Path: "../escape.md", Kind: EntryFile},
		Entry{Path: "a/b/", Kind: EntryDir},
		Entry{Path: "back\\slash.md", Kind: EntryFile},
		Entry{Path: "slug/", Kind: EntryDir},
	)
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal failed the whole manifest: %v", err)
	}
	var paths []string
	for _, e := range got.Entries {
		paths = append(paths, e.Path)
	}
	if strings.Join(paths, ",") != "back\\slash.md,good.md,slug/" {
		t.Fatalf("entries = %v, want the valid ones only", paths)
	}
	// The stripped form, which seeds the watcher's chain snapshot, agrees
	// with a producer that never emitted the dropped entries.
	stripped, err := StripStoragePtrs(b)
	if err != nil {
		t.Fatal(err)
	}
	want := New()
	want.Entries = []Entry{{Path: "good.md", Kind: EntryFile}, {Path: "back\\slash.md", Kind: EntryFile}, {Path: "slug/", Kind: EntryDir}}
	wb, _ := want.Marshal()
	if string(stripped) != string(wb) {
		t.Fatalf("stripped = %s, want %s", stripped, wb)
	}
}

// goldenTree is fixed content whose PackDir digest was recorded with the
// implementation that walked with filepath.WalkDir and os.Open (Go 1.24):
// the privsep-based walk must produce the same bytes.
func goldenTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"SOUL.md":                        "You are Sage. DeFi helper.\n",
		"nested/a.txt":                   "alpha",
		"nested/b.txt":                   "beta",
		"deep/sub/x.json":                `{"k":1}`,
		"日本/文件.md":                       "内容\n",
		strings.Repeat("n", 120) + ".md": "long name",
		"a.txt":                          "",
	}
	for rel, c := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	return dir
}

const goldenPackSHA256 = "b80f5cd8a7d302bb1968f3e128585df44c9db0153169094e54af229ea810e53f"

func TestPackDirGoldenUnchanged(t *testing.T) {
	b, err := PackDir(goldenTree(t))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != goldenPackSHA256 || len(b) != 479 {
		t.Fatalf("PackDir digest = %s (%d bytes), want %s (479 bytes)", got, len(b), goldenPackSHA256)
	}
}

func TestPackDirSkipsLinksAndSpecialFilesWithoutHanging(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("not for the archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.md"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "leak.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "leakdir")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "pipe.md"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte, 1)
	go func() {
		b, err := PackDir(dir)
		if err != nil {
			t.Error(err)
		}
		done <- b
	}()
	select {
	case b := <-done:
		if string(b) != string(baseline) {
			t.Fatal("links or a FIFO changed the archive; they must be skipped")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PackDir blocked on a FIFO")
	}
	if _, err := PackDir(filepath.Join(dir, "leakdir")); !errors.Is(err, privsep.ErrUnsafePath) {
		t.Fatalf("PackDir(link) = %v, want ErrUnsafePath", err)
	}
}

func TestUnpackDirRefusesLinkInParentOfDst(t *testing.T) {
	src := buildTree(t, map[string]string{"x.md": "x"})
	tarball, err := PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "skills")); err != nil {
		t.Fatal(err)
	}
	err = UnpackDir(tarball, filepath.Join(dir, "skills", "slug"))
	if !errors.Is(err, privsep.ErrUnsafePath) {
		t.Fatalf("UnpackDir through a linked parent = %v, want ErrUnsafePath", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("UnpackDir wrote through a link: %v", ents)
	}
	// A link planted at a file's name inside dst is replaced, not followed.
	dst := filepath.Join(dir, "real")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dst, "x.md")); err != nil {
		t.Fatal(err)
	}
	if err := UnpackDir(tarball, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("link target changed: %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(dst, "x.md")); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("x.md = %v, %v; want a regular file", fi, err)
	}
}

// A file over privsep.LimitTracked inside a directory is packed (earlier
// packers had no per-file limit, so restore writes such files back), and
// the archive round-trips. Only an archive over the bound UnpackDir
// applies is refused, with ErrTooLarge, so nothing restore would refuse is
// produced.
func TestPackDirStreamsLargeFilesAndBoundsTheTotal(t *testing.T) {
	dir := buildTree(t, map[string]string{"a.md": "a"})
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, privsep.LimitTracked+1); err != nil {
		t.Fatal(err)
	}
	tarball, err := PackDir(dir)
	if err != nil {
		t.Fatalf("PackDir with a file over LimitTracked = %v", err)
	}
	dst := filepath.Join(t.TempDir(), "out")
	if err := UnpackDir(tarball, dst); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "big.bin")); err != nil || fi.Size() != privsep.LimitTracked+1 {
		t.Fatalf("big.bin after a round trip = %v, %v", fi, err)
	}
	again, err := PackDir(dst)
	if err != nil || !bytes.Equal(again, tarball) {
		t.Fatalf("restored tree packs to different bytes (%v)", err)
	}

	prev := maxPackTotal
	maxPackTotal = privsep.LimitTracked
	t.Cleanup(func() { maxPackTotal = prev })
	if _, err := PackDir(dir); !errors.Is(err, privsep.ErrTooLarge) {
		t.Fatalf("PackDir over the archive bound = %v, want ErrTooLarge", err)
	}
	if _, _, err := PackDirDigest(dir); !errors.Is(err, privsep.ErrTooLarge) {
		t.Fatalf("PackDirDigest over the archive bound = %v, want ErrTooLarge", err)
	}
}

// The producer helpers hold an oversized entry (the uploader keeps its
// committed version) instead of failing the role or leaving it out, and
// leave out what is gone or refused.
func TestEntryHelpersHoldOversizedEntries(t *testing.T) {
	dir := buildTree(t, map[string]string{"skill/SKILL.md": "s", "note.md": "n"})
	big := filepath.Join(dir, "big.md")
	if err := os.WriteFile(big, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, privsep.LimitTracked+1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "note.md"), filepath.Join(dir, "link.md")); err != nil {
		t.Fatal(err)
	}

	e, ok, err := FileEntryOf(filepath.Join(dir, "note.md"), "note.md", nil)
	if err != nil || !ok || e.IsHeld() || e.ContentHash != HashHex([]byte("n")) || e.Kind != EntryFile {
		t.Fatalf("FileEntryOf(note.md) = %+v, %v, %v", e, ok, err)
	}
	e, ok, err = FileEntryOf(filepath.Join(dir, "note.md"), "note.md", func([]byte) []byte { return nil })
	if err != nil || !ok || e.Size != 0 || e.ContentHash != HashHex(nil) {
		t.Fatalf("FileEntryOf with a transform = %+v, %v, %v", e, ok, err)
	}
	e, ok, err = FileEntryOf(big, "big.md", nil)
	if err != nil || !ok || !e.IsHeld() || e.Path != "big.md" || e.Kind != EntryFile {
		t.Fatalf("FileEntryOf(oversized) = %+v, %v, %v; want a held file entry", e, ok, err)
	}
	for _, name := range []string{"link.md", "gone.md"} {
		if e, ok, err := FileEntryOf(filepath.Join(dir, name), name, nil); ok || err != nil {
			t.Fatalf("FileEntryOf(%s) = %+v, %v, %v; want it left out", name, e, ok, err)
		}
	}

	e, ok, err = DirEntryOf(filepath.Join(dir, "skill"), "skill")
	if err != nil || !ok || e.IsHeld() || e.Path != "skill/" || e.Kind != EntryDir {
		t.Fatalf("DirEntryOf(skill) = %+v, %v, %v", e, ok, err)
	}
	prev := maxPackTotal
	maxPackTotal = 0
	t.Cleanup(func() { maxPackTotal = prev })
	e, ok, err = DirEntryOf(filepath.Join(dir, "skill"), "skill")
	if err != nil || !ok || !e.IsHeld() || e.Path != "skill/" || e.Kind != EntryDir {
		t.Fatalf("DirEntryOf(over the bound) = %+v, %v, %v; want a held dir entry", e, ok, err)
	}
	maxPackTotal = prev
	if e, ok, err := DirEntryOf(filepath.Join(dir, "gone"), "gone"); ok || err != nil {
		t.Fatalf("DirEntryOf(gone) = %+v, %v, %v; want it left out", e, ok, err)
	}
	if Held("x", EntryFile).ContentHash == HashHex(nil) || (Entry{ContentHash: HashHex(nil)}).IsHeld() {
		t.Fatal("a held entry is indistinguishable from content")
	}
}

// An archive with a member over privsep.LimitTracked (which an earlier
// packer could commit) restores; only the total is bounded.
func TestUnpackDirRestoresLargeMemberAndBoundsTotal(t *testing.T) {
	const size = privsep.LimitTracked + 1<<20
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "big.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: size}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(tw, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "small.md", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	dst := filepath.Join(t.TempDir(), "out")
	if err := UnpackDir(buf.Bytes(), dst); err != nil {
		t.Fatalf("UnpackDir refused a large member: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "big.bin")); err != nil || fi.Size() != size {
		t.Fatalf("big.bin = %v, %v", fi, err)
	}
	prev := maxUnpackTotal
	maxUnpackTotal = size
	t.Cleanup(func() { maxUnpackTotal = prev })
	if err := UnpackDir(buf.Bytes(), filepath.Join(t.TempDir(), "out2")); err == nil {
		t.Fatal("UnpackDir exceeded the total bound")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// The depth bound is reported once per path, not on every pack.
func TestPackDirDepthLoggedOnce(t *testing.T) {
	dir := t.TempDir()
	deep := dir
	for i := 0; i < maxPackDepth+2; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := PackDir(dir); err != nil {
		t.Fatal(err)
	}
	before := len(logger.Lines())
	for i := 0; i < 3; i++ {
		if _, err := PackDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(logger.Lines()) - before; n != 0 {
		t.Fatalf("repeated packs logged %d more lines", n)
	}
}

// The watcher's hash of a directory entry is the hash of the archive an
// upload sends, and computing it does not hold the archive: what it
// allocates does not grow with the directory. (PackDir held the whole
// archive, at maximum compression, on every watcher pass: about three
// times its size in heap.)
func TestPackDirDigestDoesNotHoldTheArchive(t *testing.T) {
	dir := t.TempDir()
	const size = 24 << 20
	f, err := os.Create(filepath.Join(dir, "blob.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(f, rand.Reader, size); err != nil { // incompressible
		t.Fatal(err)
	}
	f.Close()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	hash, n, err := PackDirDigest(dir)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("PackDirDigest over %d bytes allocated %d bytes", size, alloc)
	if alloc > size/4 {
		t.Fatalf("PackDirDigest over a %d-byte directory allocated %d bytes", size, alloc)
	}

	archive, err := PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hash != HashHex(archive) || n != len(archive) {
		t.Fatalf("PackDirDigest = %s, %d; the archive PackDir returns hashes to %s, %d", hash, n, HashHex(archive), len(archive))
	}
	e, ok, err := DirEntryOf(dir, "blob")
	if err != nil || !ok || e.ContentHash != hash || e.Size != n {
		t.Fatalf("DirEntryOf = %+v, %v, %v; want the archive's hash and size", e, ok, err)
	}
}

// What is packed restores: the pack bound is within the restore bound, and
// both are what they are documented to be (the agent doc states the pack
// bound; restore must take back what earlier sealed versions committed).
func TestPackBoundIsWithinTheRestoreBound(t *testing.T) {
	if maxPackTotal > maxUnpackTotal {
		t.Fatalf("PackDir packs up to %d bytes but UnpackDir restores only %d", maxPackTotal, maxUnpackTotal)
	}
	if ArchiveLimit() != maxPackTotal {
		t.Fatalf("ArchiveLimit() = %d, want the pack bound %d", ArchiveLimit(), maxPackTotal)
	}
	if maxUnpackTotal < 4<<30 {
		t.Fatalf("UnpackDir restores only %d bytes; archives earlier sealed versions committed (up to 4 GiB) must restore", maxUnpackTotal)
	}
}
