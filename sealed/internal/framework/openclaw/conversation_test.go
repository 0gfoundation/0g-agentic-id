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

	"golang.org/x/sys/unix"

	"seal-verify/internal/inference"
)

func redirectHome(t *testing.T) {
	t.Helper()
	old := openclawHome
	openclawHome = t.TempDir()
	t.Cleanup(func() { openclawHome = old })
	isolateState(t)
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
		got, err := sessionFilesForKey(key)
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

// An agent swapping the sessions dir for a link between the read and the
// delete cannot steer the delete out of its tree: every removal walks the path
// again without following a link (privsep.Remove), so the swapped-in link
// refuses it and the directory it points at is left alone.
func TestClearSession_SwappedDirDoesNotRedirectTheDelete(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	files := plantRealSession(t, a.ConversationHeaders()[sessionKeyHeader])
	decoy := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(decoy, f), []byte("not yours"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prev := afterStoreRead
	afterStoreRead = func() {
		if err := os.Rename(sessionsDir(), sessionsDir()+".moved"); err != nil {
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
			t.Errorf("a file behind the swapped-in link was deleted: %s (%v)", f, err)
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

// The store's type is checked on the descriptor as opened, not by a path
// check before the open: an agent atomically swapping a FIFO in between must
// not be able to block /clear (a root thread) forever.
func TestClearSession_FIFOSwapRaceDoesNotHang(t *testing.T) {
	redirectHome(t)
	dir := sessionsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sessions.json"), []byte(`{"agent:main:k":{"sessionId":"abc"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "other"), 0o644); err != nil {
		t.Skipf("no FIFO support: %v", err)
	}
	swap := func() error {
		return unix.Renameat2(unix.AT_FDCWD, filepath.Join(dir, "sessions.json"), unix.AT_FDCWD, filepath.Join(dir, "other"), unix.RENAME_EXCHANGE)
	}
	if err := swap(); err != nil {
		t.Skipf("no RENAME_EXCHANGE here: %v", err)
	}
	stop := make(chan struct{})
	go func() { // the hostile agent: swap the two names, forever
		for {
			select {
			case <-stop:
				return
			default:
				_ = swap()
			}
		}
	}()
	defer close(stop)
	for i := 0; i < 200; i++ {
		done := make(chan struct{})
		go func() { removeSessionFiles("k"); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("attempt %d: removeSessionFiles blocked on a FIFO swapped in", i)
		}
	}
}

// A container upgraded in place keeps its conversation: the session key an
// earlier sealed pinned in the openclaw tree is taken over once (and the old
// file retired); a file that is not a key this platform minted is ignored.
func TestConversationKey_TakesOverTheEarlierSealedsKey(t *testing.T) {
	useTempHome(t)
	const old = "seal-owner-chat-0123456789abcdef01234567"
	legacy := legacyConversationKeyPath()
	if err := os.WriteFile(legacy, []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	if got := a.ConversationHeaders()[sessionKeyHeader]; got != old {
		t.Fatalf("key = %q, want the earlier sealed's %q", got, old)
	}
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("the earlier key file was not retired: %v", err)
	}
	if got := a.ConversationHeaders()[sessionKeyHeader]; got != old {
		t.Fatalf("key after the move = %q", got)
	}

	for _, bad := range []string{"agent-chosen-key", "seal-owner-chat-XYZ", "seal-owner-chat-0123456789ABCDEF01234567"} {
		useTempHome(t)
		if err := os.WriteFile(legacyConversationKeyPath(), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := a.ConversationHeaders()[sessionKeyHeader]; got == bad || !isMintedConversationKey(got) {
			t.Fatalf("legacy %q: key = %q, want a freshly minted one", bad, got)
		}
	}
}

// An earlier sealed's key that cannot be read for now — its owner holds a
// lease on the file — is not taken for absent: the turn gets a fresh key
// that is not persisted, and once the lease is gone the earlier key is
// taken over after all, so the conversation does not fork for good.
func TestConversationKey_LeasedEarlierKeyIsNotForgotten(t *testing.T) {
	useTempHome(t)
	const old = "seal-owner-chat-0123456789abcdef01234567"
	legacy := legacyConversationKeyPath()
	if err := os.WriteFile(legacy, []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := unix.Open(legacy, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(holder)
	if _, err := unix.FcntlInt(uintptr(holder), unix.F_SETLEASE, unix.F_WRLCK); err != nil {
		skipOrFail(t, "cannot take a lease on %s here: %v", legacy, err)
	}
	a := New()
	if got := a.ConversationHeaders()[sessionKeyHeader]; got == old || !isMintedConversationKey(got) {
		t.Fatalf("key while leased = %q, want a fresh one", got)
	}
	if _, err := os.Lstat(conversationKeyPath()); !os.IsNotExist(err) {
		t.Fatalf("a key was persisted while the earlier one could not be read: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(holder), unix.F_SETLEASE, unix.F_UNLCK); err != nil {
		t.Fatal(err)
	}
	if got := a.ConversationHeaders()[sessionKeyHeader]; got != old {
		t.Fatalf("key once the lease is gone = %q, want the earlier sealed's %q", got, old)
	}
}

// The applied-overlay record an earlier sealed kept in the openclaw tree is
// read once, so an overlay key the owner removed around the upgrade is still
// withdrawn, and the render retires the old record.
func TestAppliedOverlay_ReadsTheEarlierSealedsRecord(t *testing.T) {
	useTempHome(t)
	if err := os.MkdirAll(openclawHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openclawJSONPath(), []byte(`{"agents":{"defaults":{"maxConcurrent":2}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := legacyAppliedOverlayPath()
	if err := os.WriteFile(legacy, []byte(`{"agents":{"defaults":{"maxConcurrent":2}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	if _, still := defaults["maxConcurrent"]; still {
		t.Fatal("a key the earlier sealed's record says the overlay set, and the overlay no longer carries, was left in openclaw.json")
	}
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("the earlier record was not retired: %v", err)
	}
	// Once sealed has a record of its own (even of an empty overlay), a
	// record the agent writes at the old name is never read again.
	if err := os.WriteFile(legacy, []byte(`{"diagnostics":{"stuckSessionAbortMs":900000}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadAppliedOverlay(); len(got) != 0 {
		t.Fatalf("loadAppliedOverlay = %v after sealed saved its own record; want the empty overlay recorded", got)
	}
}
