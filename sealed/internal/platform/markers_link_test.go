package platform

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A link planted at an injected file's name is replaced with a regular file;
// its target is neither read into the result nor written.
func TestUpsertMarkedSectionReplacesLink(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("root-only bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	soul := filepath.Join(dir, "SOUL.md")
	if err := os.Symlink(outside, soul); err != nil {
		t.Fatal(err)
	}
	if err := UpsertMarkedSection(soul, "platform text"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "root-only bytes\n" {
		t.Fatalf("link target changed: %q", b)
	}
	fi, err := os.Lstat(soul)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("SOUL.md = %v, %v; want a regular file", fi, err)
	}
	b, _ := os.ReadFile(soul)
	if strings.Contains(string(b), "root-only") {
		t.Fatalf("target content leaked into the rewritten file: %q", b)
	}
	if !strings.Contains(string(b), "platform text") {
		t.Fatalf("section missing: %q", b)
	}
}

// A socket at an injected file's name is refused by the read like a FIFO
// (not opened), counts as empty, and is replaced with a regular file.
func TestUpsertMarkedSectionReplacesSocket(t *testing.T) {
	dir := t.TempDir()
	soul := filepath.Join(dir, "SOUL.md")
	l, err := net.Listen("unix", soul)
	if err != nil {
		t.Skipf("cannot bind a unix socket here: %v", err)
	}
	defer l.Close()
	if err := UpsertMarkedSection(soul, "platform text"); err != nil {
		t.Fatalf("UpsertMarkedSection over a socket: %v", err)
	}
	fi, err := os.Lstat(soul)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("SOUL.md = %v, %v; want a regular file", fi, err)
	}
	if b, _ := os.ReadFile(soul); !strings.Contains(string(b), "platform text") {
		t.Fatalf("section missing: %q", b)
	}
}

// A directory at an injected file's name is replaced with a regular file,
// as the rewrite promises, rather than failing every start.
func TestUpsertMarkedSectionReplacesDirectory(t *testing.T) {
	dir := t.TempDir()
	soul := filepath.Join(dir, "SOUL.md")
	if err := os.MkdirAll(filepath.Join(soul, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := UpsertMarkedSection(soul, "platform text"); err != nil {
		t.Fatalf("UpsertMarkedSection over a directory: %v", err)
	}
	fi, err := os.Lstat(soul)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("SOUL.md = %v, %v; want a regular file", fi, err)
	}
	if b, _ := os.ReadFile(soul); !strings.Contains(string(b), "platform text") {
		t.Fatalf("section missing: %q", b)
	}
}
