package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// buildHostileTar produces a tar.gz with a single entry at entryName.
// Used by tests that verify UnpackDir rejects unsafe paths.
func buildHostileTar(t *testing.T, entryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     entryName,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
		Format:   tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// buildTree creates a temp directory populated with the given (relpath, content)
// pairs. Directories are created automatically. Returns the temp dir.
func buildTree(t *testing.T, entries map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range entries {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return dir
}

func TestPackDir_DeterministicSameInputSameOutput(t *testing.T) {
	tree := map[string]string{
		"SOUL.md":         "You are Sage. DeFi helper.\n",
		"IDENTITY.md":     "name: Sage\nstyle: friendly\n",
		"nested/a.txt":    "alpha",
		"nested/b.txt":    "beta",
		"deep/sub/x.json": `{"k":1}`,
	}
	dirA := buildTree(t, tree)
	dirB := buildTree(t, tree)

	bytesA, err := PackDir(dirA)
	if err != nil {
		t.Fatalf("PackDir A: %v", err)
	}
	bytesB, err := PackDir(dirB)
	if err != nil {
		t.Fatalf("PackDir B: %v", err)
	}
	if !bytes.Equal(bytesA, bytesB) {
		t.Errorf("PackDir not deterministic: lenA=%d lenB=%d hashA=%x hashB=%x",
			len(bytesA), len(bytesB), sha256.Sum256(bytesA), sha256.Sum256(bytesB))
	}
}

func TestPackDir_DifferentContentDifferentOutput(t *testing.T) {
	dirA := buildTree(t, map[string]string{"a.txt": "alpha"})
	dirB := buildTree(t, map[string]string{"a.txt": "alpha modified"})

	bytesA, _ := PackDir(dirA)
	bytesB, _ := PackDir(dirB)
	if bytes.Equal(bytesA, bytesB) {
		t.Errorf("different content produced identical tar bytes")
	}
}

func TestPackDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	out, err := PackDir(dir)
	if err != nil {
		t.Fatalf("PackDir empty: %v", err)
	}
	// Empty tar.gz is small but non-zero; second call must produce same bytes.
	out2, err := PackDir(dir)
	if err != nil {
		t.Fatalf("PackDir empty #2: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Errorf("empty dir tar not deterministic")
	}
	// Unpack should produce an empty dir.
	dst := t.TempDir()
	if err := UnpackDir(out, dst); err != nil {
		t.Fatalf("UnpackDir empty: %v", err)
	}
	entries, _ := os.ReadDir(dst)
	if len(entries) != 0 {
		t.Errorf("unpacked empty dir has %d entries; want 0", len(entries))
	}
}

func TestPackDir_NonAsciiPathsAndContent(t *testing.T) {
	tree := map[string]string{
		"中文.md":         "用户文档\n",
		"emoji-🦊.txt":    "fox content",
		"sub/日本語/x.txt": "kanji here",
	}
	dirA := buildTree(t, tree)
	dirB := buildTree(t, tree)

	bytesA, err := PackDir(dirA)
	if err != nil {
		t.Fatalf("PackDir A: %v", err)
	}
	bytesB, err := PackDir(dirB)
	if err != nil {
		t.Fatalf("PackDir B: %v", err)
	}
	if !bytes.Equal(bytesA, bytesB) {
		t.Errorf("non-ASCII paths not deterministic")
	}
	// Roundtrip.
	dst := t.TempDir()
	if err := UnpackDir(bytesA, dst); err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}
	for rel, want := range tree {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Errorf("missing after unpack: %s: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("content mismatch for %s: got %q, want %q", rel, got, want)
		}
	}
}

func TestRoundtrip_PackUnpackProducesSameTree(t *testing.T) {
	original := map[string]string{
		"top.txt":       "a",
		"sub/inner.txt": "b",
		"sub/deep/x":    "c",
	}
	src := buildTree(t, original)
	packed, err := PackDir(src)
	if err != nil {
		t.Fatalf("PackDir: %v", err)
	}
	dst := t.TempDir()
	if err := UnpackDir(packed, dst); err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}
	// Re-pack the unpacked tree and verify identical bytes.
	repacked, err := PackDir(dst)
	if err != nil {
		t.Fatalf("PackDir repacked: %v", err)
	}
	if !bytes.Equal(packed, repacked) {
		t.Errorf("pack→unpack→pack not stable")
	}
}

func TestUnpackDir_RejectsAbsolutePath(t *testing.T) {
	// Manually craft a malicious tar.gz with an entry name that's absolute.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "ok.txt"), []byte("safe"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	packed, err := PackDir(src)
	if err != nil {
		t.Fatalf("PackDir: %v", err)
	}
	// Replace "ok.txt" header path with "/etc/evil" by surgical patch isn't
	// trivial without re-implementing tar; instead build a hostile tar directly.
	hostile := buildHostileTar(t, "/etc/evil", []byte("pwned"))
	if err := UnpackDir(hostile, t.TempDir()); err == nil {
		t.Errorf("expected error unpacking absolute-path entry, got nil")
	}
	// And confirm the safe tar still unpacks fine to ensure the rejection isn't
	// blanket.
	dst := t.TempDir()
	if err := UnpackDir(packed, dst); err != nil {
		t.Errorf("safe tar should unpack: %v", err)
	}
}

func TestUnpackDir_RejectsPathEscape(t *testing.T) {
	hostile := buildHostileTar(t, "../../etc/evil", []byte("pwned"))
	if err := UnpackDir(hostile, t.TempDir()); err == nil {
		t.Errorf("expected error unpacking ../-escape entry, got nil")
	}
}

func TestPackDir_FileModeNormalised(t *testing.T) {
	// Create files with unusual modes; tar output should normalise to 0644.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o777); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b"), []byte("y"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	bytesA, _ := PackDir(dir)

	// Now chmod and re-pack — should produce same bytes.
	if err := os.Chmod(filepath.Join(dir, "a"), 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	bytesB, _ := PackDir(dir)
	if !bytes.Equal(bytesA, bytesB) {
		t.Errorf("mode change leaked into tar output (mode not normalised)")
	}
}
