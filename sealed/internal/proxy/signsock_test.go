package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"seal-verify/internal/state"
)

// A stale entry at the socket path is removed itself, never followed, and
// the new socket ends up 0600.
func TestListenInternalReplacesALinkAtTheSocketPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sign.sock")
	if err := os.Symlink(target, sock); err != nil {
		t.Fatal(err)
	}
	New(state.New(), "http://x").ListenInternal(sock)

	if b, err := os.ReadFile(target); err != nil || string(b) != "keep" {
		t.Fatalf("link target changed: %q, %v", b, err)
	}
	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket path = %v, want a 0600 socket", fi.Mode())
	}
}

// The agent log is read as a bounded tail.
func TestReadAgentLogIsBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.log")
	big := make([]byte, agentLogTailBytes+10)
	for i := range big {
		big[i] = 'a'
	}
	copy(big[len(big)-4:], "tail")
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := readAgentLog(p)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) != agentLogTailBytes || string(b[len(b)-4:]) != "tail" {
		t.Fatalf("read %d bytes ending %q, want the last %d", len(b), b[len(b)-4:], agentLogTailBytes)
	}
}
