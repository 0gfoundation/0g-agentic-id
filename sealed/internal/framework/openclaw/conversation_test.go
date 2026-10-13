package openclaw

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func redirectHome(t *testing.T) {
	t.Helper()
	old := openclawHome
	openclawHome = t.TempDir()
	t.Cleanup(func() { openclawHome = old })
}

// Write an openclaw-shaped store + transcript for the pinned key.
func plantTranscript(t *testing.T, key string, lines []string) string {
	t.Helper()
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	tp := filepath.Join(sessionsDir(), "sess-1.jsonl")
	store := map[string]sessionEntry{key: {SessionID: "sess-1"}}
	raw, _ := json.Marshal(store)
	if err := os.WriteFile(sessionsStorePath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(tp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return tp
}

// The real v3 transcript shape: header line, then message records whose
// content is a string OR an array of typed parts. Foreign records skip.
func TestConversationHistory_ReadsOpenclawTranscript(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	key := a.ConversationHeaders()[sessionKeyHeader]
	plantTranscript(t, key, []string{
		`{"type":"session","version":3,"id":"sess-1","timestamp":"2026-09-29T00:00:00Z","cwd":"/root"}`,
		`{"type":"message","id":"m1","message":{"role":"user","content":"codeword lychee42"}}`,
		`{"type":"message","id":"m2","message":{"role":"assistant","content":[{"type":"text","text":"noted: "},{"type":"text","text":"lychee42"}],"usage":{"input":1}}}`,
		`{"type":"custom","id":"m3"}`,
		`{"type":"message","id":"m4","message":{"role":"toolResult","content":"skipped"}}`,
		`{"type":"message","id":"m5","message":` /* torn crash tail */,
	})
	turns, err := a.ConversationHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(turns) != 2 {
		t.Fatalf("want 2 turns, got %d: %+v", len(turns), turns)
	}
	if turns[0].Role != "user" || turns[0].Text != "codeword lychee42" {
		t.Fatalf("user turn wrong: %+v", turns[0])
	}
	if turns[1].Role != "assistant" || turns[1].Text != "noted: lychee42" {
		t.Fatalf("assistant parts must flatten: %+v", turns[1])
	}
}

// No store / no session yet is DATA (a first conversation), never an error.
func TestConversationHistory_FreshAgentIsEmptyNotError(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	turns, err := a.ConversationHistory(context.Background())
	if err != nil || turns != nil {
		t.Fatalf("fresh agent: turns=%v err=%v, want nil/nil", turns, err)
	}
}

// The pinned key is minted once and stable — one conversation per agent.
func TestConversationKey_Stable(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	k1 := a.ConversationHeaders()[sessionKeyHeader]
	k2 := a.ConversationHeaders()[sessionKeyHeader]
	if k1 == "" || k1 != k2 {
		t.Fatalf("key must be stable: %q vs %q", k1, k2)
	}
}

// /clear rotates the key and removes the superseded transcript; openclaw's
// own sessions.json is left alone (its store, its write cycle).
func TestClearSession_RotatesKeyAndRemovesTranscript(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	key := a.ConversationHeaders()[sessionKeyHeader]
	tp := plantTranscript(t, key, []string{`{"type":"session","version":3,"id":"sess-1"}`})
	if err := a.ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.ConversationHeaders()[sessionKeyHeader]; got == key {
		t.Fatal("key must rotate on clear")
	}
	if _, err := os.Stat(tp); !os.IsNotExist(err) {
		t.Fatalf("superseded transcript must be removed: %v", err)
	}
	if _, err := os.Stat(sessionsStorePath()); err != nil {
		t.Fatalf("openclaw's own store must be left alone: %v", err)
	}
	turns, err := a.ConversationHistory(context.Background())
	if err != nil || len(turns) != 0 {
		t.Fatalf("after clear the conversation is fresh: %v %v", turns, err)
	}
}

// sessions.json is agent-writable (privsep hands openclawHome to the framework
// user), so a sessionFile it names must never walk the root-running adapter
// out of sessionsDir() — that read is piped into the next upstream body.
func TestTranscriptPath_ContainsAgentWritableStore(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	key := a.ConversationHeaders()[sessionKeyHeader]
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		entry sessionEntry
		want  string // "" = refused/empty
	}{
		{"absolute escape", sessionEntry{SessionFile: "/etc/shadow"}, ""},
		{"dotdot escape", sessionEntry{SessionFile: sessionsDir() + "/../../../etc/shadow"}, ""},
		{"path-shaped id", sessionEntry{SessionID: "../../etc/passwd"}, ""},
		{"legit absolute", sessionEntry{SessionFile: sessionsDir() + "/ok.jsonl"}, sessionsDir() + "/ok.jsonl"},
		{"legit id", sessionEntry{SessionID: "sess-9"}, sessionsDir() + "/sess-9.jsonl"},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(map[string]sessionEntry{key: c.entry})
		if err := os.WriteFile(sessionsStorePath(), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := transcriptPathForKey(key)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// Lexical containment cannot stop a symlink planted INSIDE the agent-writable
// sessionsDir; os.OpenRoot must refuse to follow it out (review #169
// hardening note). The turn degrades to empty history, never reads the target.
func TestConversationHistory_RefusesSymlinkEscape(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	key := a.ConversationHeaders()[sessionKeyHeader]
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "root-only.txt")
	if err := os.WriteFile(secret, []byte(`{"type":"message","id":"x","message":{"role":"user","content":"EXFILTRATED"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A legit-named transcript that is actually a symlink out of the dir.
	if err := os.Symlink(secret, filepath.Join(sessionsDir(), "sess-evil.jsonl")); err != nil {
		t.Skipf("no symlink support: %v", err)
	}
	raw, _ := json.Marshal(map[string]sessionEntry{key: {SessionID: "sess-evil"}})
	if err := os.WriteFile(sessionsStorePath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	turns, err := a.ConversationHistory(context.Background())
	if err != nil {
		t.Fatalf("must degrade, not error: %v", err)
	}
	if len(turns) != 0 {
		t.Fatalf("symlink escape was followed: %+v", turns)
	}
}
