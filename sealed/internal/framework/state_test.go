package framework

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// OpenLog is one of the few direct os calls outside privsep
// (allowedDirectCalls): its file is opened O_NOFOLLOW, so a link planted at
// the log's name is refused rather than followed.
func TestOpenLogRefusesALink(t *testing.T) {
	prev := StateDir
	StateDir = t.TempDir()
	t.Cleanup(func() { StateDir = prev })
	if err := os.MkdirAll(filepath.Join(StateDir, "log"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, LogPath("fw")); err != nil {
		t.Fatal(err)
	}
	f, err := OpenLog("fw")
	if err == nil {
		f.Close()
		t.Fatal("OpenLog followed a link at the log's name")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("OpenLog = %v, want ELOOP", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatalf("link target changed: %q", b)
	}
}
