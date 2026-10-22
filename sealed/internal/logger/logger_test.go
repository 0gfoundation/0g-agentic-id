package logger

import (
	"fmt"
	"strings"
	"testing"
)

// Once logs a key once, and a flood of keys in one namespace neither grows
// the log past the cap nor silences another namespace.
func TestOnceIsBoundedPerNamespace(t *testing.T) {
	before := len(Lines())
	if !Once("test-a:x", "first") || Once("test-a:x", "again") {
		t.Fatal("Once did not log exactly once for a key")
	}
	for i := 0; i < maxOnceKeys+100; i++ {
		Once(fmt.Sprintf("test-flood:%d", i), "flood %d", i)
	}
	if n := len(Lines()) - before; n != 1+maxOnceKeys {
		t.Fatalf("logged %d lines, want %d", n, 1+maxOnceKeys)
	}
	if !Once("test-b:y", "other namespace") {
		t.Fatal("a flood in one namespace silenced another")
	}
}

// A message cannot start a line of its own: text after a newline in it is
// marked as a continuation, and other control characters (a carriage
// return, an escape sequence) are escaped, so a file name or command
// output the agent controls cannot forge an entry in /log.
func TestLogfCannotForgeAnEntry(t *testing.T) {
	before := len(Lines())
	forged := "[12:00:00.000] OK   uploader.Apply: submitting wholesale update tx"
	Logf("privsep: skipping %s: refused", "/root/.openclaw/workspace/skills/a\n"+forged)
	Logf("validator said: %s", "line one\r"+forged+"\x1b[2K\u2028x\tend")
	got := Lines()[before:]
	if len(got) != 2 {
		t.Fatalf("logged %d entries, want 2", len(got))
	}
	for _, entry := range got {
		for i, line := range strings.Split(entry, "\n") {
			if i > 0 && !strings.HasPrefix(line, continuation) {
				t.Errorf("entry %q: line %d %q does not start with the continuation marker", entry, i, line)
			}
			if strings.ContainsAny(line, "\r\x1b\u2028") {
				t.Errorf("entry %q keeps a raw control character", entry)
			}
		}
	}
	snap := Snapshot()
	for _, line := range strings.Split(snap, "\n") {
		if strings.HasPrefix(line, forged) {
			t.Fatalf("/log holds a forged line: %q", line)
		}
	}
	if !strings.Contains(got[1], `\x0d`) || !strings.Contains(got[1], `\x1b`) || !strings.Contains(got[1], `\u2028`) || !strings.Contains(got[1], "\tend") {
		t.Fatalf("control characters not escaped as expected: %q", got[1])
	}
}
