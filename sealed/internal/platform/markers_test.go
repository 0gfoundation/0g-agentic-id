package platform

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// upsert writes body into a temp file pre-seeded with owner content and
// returns the resulting file bytes.
func upsert(t *testing.T, owner []byte, body string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "TOOLS.md")
	if owner != nil {
		if err := os.WriteFile(path, owner, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpsertMarkedSection(path, body); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The core contract: StripInjected(UpsertMarkedSection(owner, body)) ==
// owner, byte-exactly, for every owner shape.
func TestRoundTrip_OwnerBytesExact(t *testing.T) {
	cases := map[string][]byte{
		"trailing newline":    []byte("my notes\n"),
		"no trailing newline": []byte("my notes"),
		"empty":               []byte(""),
		"only newlines":       []byte("\n\n\n"),
		"crlf":                []byte("a\r\nb\r"),
		"unicode":             []byte("笔记 A\n笔记 B\n"),
	}
	for name, owner := range cases {
		got := StripInjected(upsert(t, owner, "platform text\n"))
		if !bytes.Equal(got, owner) {
			t.Errorf("%s: round-trip mismatch\n owner: %q\n got:   %q", name, owner, got)
		}
	}
}

func TestUpsert_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "TOOLS.md")
	if err := os.WriteFile(path, []byte("owner\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := UpsertMarkedSection(path, "v2\n"); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(path)
	if c := bytes.Count(got, []byte(MarkerStart)); c != 1 {
		t.Fatalf("want exactly 1 section after re-upserts, got %d:\n%s", c, got)
	}
	if !bytes.Equal(StripInjected(got), []byte("owner\n")) {
		t.Fatalf("owner bytes lost across re-upserts: %q", StripInjected(got))
	}
}

// Body without a trailing newline is normalized so MarkerEnd still sits
// on its own line and the round-trip holds.
func TestUpsert_BodyWithoutTrailingNewline(t *testing.T) {
	owner := []byte("owner\n")
	got := StripInjected(upsert(t, owner, "no trailing newline"))
	if !bytes.Equal(got, owner) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestUpsert_EmptyBodyStripsSection(t *testing.T) {
	owner := []byte("owner\n")
	path := filepath.Join(t.TempDir(), "TOOLS.md")
	if err := os.WriteFile(path, owner, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpsertMarkedSection(path, "body\n"); err != nil {
		t.Fatal(err)
	}
	if err := UpsertMarkedSection(path, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, owner) {
		t.Fatalf("empty-body upsert must restore owner bytes, got %q", got)
	}
}

// The agent sees the marker strings in its context files every turn, so
// its own prose may quote them. A mid-line mention is owner content —
// the historical first-index scan treated it as the section start and
// deleted everything from the quote to the real end marker.
func TestStrip_QuotedMarkerMidLine_IsOwnerContent(t *testing.T) {
	owner := []byte(
		"note: sealed injects via " + MarkerStart + " markers\n" +
			"important notes below the quote\n" +
			"more notes\n")
	got := StripInjected(upsert(t, owner, "platform text\n"))
	if !bytes.Equal(got, owner) {
		t.Fatalf("owner bytes destroyed by quoted marker:\n want %q\n got  %q", owner, got)
	}
}

func TestStrip_QuotedMarkerPair_NoRealSection_Unchanged(t *testing.T) {
	owner := []byte("the pair is " + MarkerStart + " and " + MarkerEnd + " on one line\n")
	if got := StripInjected(owner); !bytes.Equal(got, owner) {
		t.Fatalf("quoted pair without a real section must pass through, got %q", got)
	}
}

// A line-anchored start with no end anywhere is owner content, not a
// section: stripping must not truncate the file to EOF.
func TestStrip_AnchoredStartWithoutEnd_Unchanged(t *testing.T) {
	owner := []byte("notes A\n" + MarkerStart + "\nnotes B that must survive\n")
	if got := StripInjected(owner); !bytes.Equal(got, owner) {
		t.Fatalf("unpaired start must strip nothing:\n want %q\n got  %q", owner, got)
	}
}

// Documented residual ambiguity: an agent-written EXACT reproduction of
// the wire format (both markers, each on its own line) is byte-wise
// indistinguishable from a real section, so the next upsert treats it as
// the previous injection and removes it — the reproduced pair, what it
// encloses, and the preceding newline (taken for the section's own
// separator). The rest of the owner bytes survive.
func TestStrip_ExactAnchoredPairInOwnerContent_IsAmbiguous(t *testing.T) {
	owner := []byte(
		"copied for reference:\n" +
			MarkerStart + "\nfake\n" + MarkerEnd + "\n" +
			"notes after the copy\n")
	got := StripInjected(upsert(t, owner, "platform text\n"))
	want := []byte("copied for reference:notes after the copy\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("ambiguous exact pair:\n want %q\n got  %q", want, got)
	}
}

// Owner content appended by the agent BELOW the injected section is
// preserved (the section need not terminate the file at strip time).
func TestStrip_OwnerContentAfterSection(t *testing.T) {
	file := upsert(t, []byte("above\n"), "platform text\n")
	file = append(file, []byte("appended later by the agent\n")...)
	want := []byte("above\nappended later by the agent\n")
	if got := StripInjected(file); !bytes.Equal(got, want) {
		t.Fatalf("content after section lost:\n want %q\n got  %q", want, got)
	}
}

func TestStrip_NoMarkers_PassThrough(t *testing.T) {
	owner := []byte("plain file\n")
	if got := StripInjected(owner); !bytes.Equal(got, owner) {
		t.Fatalf("marker-free content must pass through, got %q", got)
	}
}
