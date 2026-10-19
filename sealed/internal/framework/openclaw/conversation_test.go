package openclaw

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"seal-verify/internal/inference"
)

func redirectHome(t *testing.T) {
	t.Helper()
	old := openclawHome
	openclawHome = t.TempDir()
	t.Cleanup(func() { openclawHome = old })
}

// plantSession writes an openclaw-shaped store entry under storeKey and the
// named files (relative to sessionsDir) with their content.
func plantSession(t *testing.T, storeKey string, entry sessionEntry, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]sessionEntry{storeKey: entry})
	if err := os.WriteFile(sessionsStorePath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(sessionsDir(), name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The shape openclaw 2026.7.1 writes: the session filed under
// "agent:main:<key>", an absolute sessionFile, and a trajectory record plus
// its pointer next to the transcript.
func plantRealSession(t *testing.T, key string) []string {
	t.Helper()
	files := []string{"sess-1.jsonl", "sess-1.trajectory.jsonl", "sess-1.trajectory-path.json"}
	plantSession(t, "agent:main:"+key,
		sessionEntry{SessionID: "sess-1", SessionFile: filepath.Join(sessionsDir(), "sess-1.jsonl")},
		map[string]string{
			files[0]: `{"type":"message","id":"m1","message":{"role":"user","content":"codeword lychee42"}}` + "\n",
			files[1]: `{"type":"prompt.submitted","data":"codeword lychee42"}` + "\n",
			files[2]: `{"traceSchema":"openclaw-trajectory-pointer","schemaVersion":1,"sessionId":"sess-1"}`,
		})
	return files
}

// The gateway replays the pinned session itself, so the door must send only
// the current turn: the hook returns no prior turns even with a transcript
// full of them on disk.
func TestConversationHistory_SendsOnlyTheCurrentTurn(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	plantRealSession(t, a.ConversationHeaders()[sessionKeyHeader])
	turns, err := a.ConversationHistory(context.Background())
	if err != nil || turns != nil {
		t.Fatalf("turns=%v err=%v; want nil/nil — prepending history would duplicate the gateway's replay", turns, err)
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

// /clear rotates the key and deletes the superseded session's files — the
// transcript AND the trajectory, which holds the same conversation — found
// under the key openclaw actually files it by. Another session's files and
// openclaw's own sessions.json are left alone.
func TestClearSession_RemovesTheSupersededSessionFiles(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	key := a.ConversationHeaders()[sessionKeyHeader]
	files := plantRealSession(t, key)
	other := filepath.Join(sessionsDir(), "sess-other.jsonl")
	if err := os.WriteFile(other, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := a.ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.ConversationHeaders()[sessionKeyHeader]; got == key {
		t.Fatal("key must rotate on clear")
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(sessionsDir(), f)); !os.IsNotExist(err) {
			t.Errorf("superseded %s must be removed: %v", f, err)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("another session's file must survive: %v", err)
	}
	if _, err := os.Stat(sessionsStorePath()); err != nil {
		t.Errorf("openclaw's own store must be left alone: %v", err)
	}
}

// A store filed under the bare key (an openclaw that does not prefix it) is
// found too.
func TestClearSession_BareKeyStore(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	key := a.ConversationHeaders()[sessionKeyHeader]
	plantSession(t, key, sessionEntry{SessionID: "sess-2"}, map[string]string{"sess-2.jsonl": "{}\n"})
	if err := a.ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sessionsDir(), "sess-2.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("transcript under the bare key must be removed: %v", err)
	}
}

// sessions.json is agent-writable (privsep hands openclawHome to the framework
// user) and the ROOT process deletes what it names, so only plain file names
// directly inside the sessions dir survive — never a path.
func TestSessionFiles_ContainsAgentWritableStore(t *testing.T) {
	redirectHome(t)
	key := "k"
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	triple := func(stem string) []string {
		return []string{stem + ".jsonl", stem + ".trajectory.jsonl", stem + ".trajectory-path.json"}
	}
	cases := []struct {
		name  string
		entry sessionEntry
		want  []string // nil = refused/empty
	}{
		{"absolute escape", sessionEntry{SessionFile: "/etc/shadow"}, nil},
		{"dotdot escape", sessionEntry{SessionFile: sessionsDir() + "/../../../etc/shadow"}, nil},
		{"subdirectory", sessionEntry{SessionFile: sessionsDir() + "/sub/x.jsonl"}, nil},
		{"path-shaped id", sessionEntry{SessionID: "../../etc/passwd"}, nil},
		{"backslash id", sessionEntry{SessionID: `a\b`}, nil},
		{"dotdot id", sessionEntry{SessionID: ".."}, nil},
		{"legit absolute", sessionEntry{SessionFile: sessionsDir() + "/ok.jsonl"}, triple("ok")},
		{"legit id", sessionEntry{SessionID: "sess-9"}, triple("sess-9")},
		{"both agree", sessionEntry{SessionID: "s", SessionFile: sessionsDir() + "/s.jsonl"}, triple("s")},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(map[string]sessionEntry{"agent:main:" + key: c.entry})
		if err := os.WriteFile(sessionsStorePath(), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(sessionsDir())
		if err != nil {
			t.Fatal(err)
		}
		got, err := sessionFilesForKey(root, key)
		root.Close()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !slices.Equal(got, c.want) {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// A symlink planted INSIDE the agent-writable sessions dir under a legit name
// is removed itself; what it points at is never touched.
func TestClearSession_DoesNotFollowSymlinks(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	key := a.ConversationHeaders()[sessionKeyHeader]
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "root-only.jsonl")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(sessionsDir(), "sess-evil.jsonl")); err != nil {
		t.Skipf("no symlink support: %v", err)
	}
	plantSession(t, "agent:main:"+key, sessionEntry{SessionID: "sess-evil"}, nil)

	if err := a.ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "precious" {
		t.Fatalf("the symlink's target was touched: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(sessionsDir(), "sess-evil.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("the planted link itself should be gone: %v", err)
	}
}

// The store is read and the files removed through ONE directory handle: an
// agent swapping the sessions dir for a symlink between the read and the
// delete cannot steer the delete into another directory — it still lands in
// the directory whose store named the files.
func TestClearSession_DeletesWhereTheStoreWasRead(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	files := plantRealSession(t, a.ConversationHeaders()[sessionKeyHeader])
	decoy := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(decoy, f), []byte("not yours"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	moved := sessionsDir() + ".moved"
	prev := afterStoreRead
	afterStoreRead = func() {
		if err := os.Rename(sessionsDir(), moved); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(decoy, sessionsDir()); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterStoreRead = prev })

	if err := a.ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(decoy, f)); err != nil {
			t.Errorf("a file in the swapped-in directory was deleted: %s (%v)", f, err)
		}
		if _, err := os.Stat(filepath.Join(moved, f)); !os.IsNotExist(err) {
			t.Errorf("%s should be gone from the directory the store was read in: %v", f, err)
		}
	}
}

// A FIFO planted as sessions.json must not hang /clear.
func TestClearSession_FIFOStoreDoesNotHang(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	a.ConversationHeaders()
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(sessionsStorePath(), 0o644); err != nil {
		t.Skipf("no FIFO support: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- a.ClearSession(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clear must still succeed (key rotated): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ClearSession hung on a FIFO sessions.json")
	}
}

// openclaw's default session policy starts a new session daily at 04:00,
// silently ending the ONE conversation; the render sets a reset policy that
// never goes stale ({mode:"idle"} with no window) — unless the owner's
// overlay sets one.
func TestRenderSettings_SessionNeverResets(t *testing.T) {
	reset := func(cfg map[string]any) any {
		session, _ := cfg["session"].(map[string]any)
		return session["reset"]
	}
	t.Run("default", func(t *testing.T) {
		useTempHome(t)
		got := reset(renderInto(t, routedSettings(inference.WireOpenAI, "glm-5.3")))
		r, _ := got.(map[string]any)
		if r == nil || r["mode"] != "idle" || len(r) != 1 {
			t.Fatalf("session.reset = %v; want {mode: idle} with no idleMinutes", got)
		}
	})
	t.Run("the overlay's policy stands", func(t *testing.T) {
		useTempHome(t)
		s := routedSettings(inference.WireOpenAI, "glm-5.3")
		s.Others = json.RawMessage(`{"session":{"reset":{"mode":"daily","atHour":5}}}`)
		r, _ := reset(renderInto(t, s)).(map[string]any)
		if r == nil || r["mode"] != "daily" || r["atHour"] != float64(5) {
			t.Fatalf("session.reset = %v; want the overlay's daily/5", r)
		}
	})
}
