package dsh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
)

func TestLinkedAppendSystemIsNotFollowed(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, appendSystemPath()); err != nil {
		t.Fatal(err)
	}
	got, err := a.evoAppendSystem()
	if err != nil || got != nil {
		t.Fatalf("evoAppendSystem through a link = %q, %v; want nothing", got, err)
	}
	if err := a.restoreAppendSystem([]byte("persona\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatalf("link target changed: %q", b)
	}
	fi, err := os.Lstat(appendSystemPath())
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("APPEND_SYSTEM.md = %v, %v; want a regular file", fi, err)
	}
	if b, _ := os.ReadFile(appendSystemPath()); strings.Contains(string(b), "keep") {
		t.Fatalf("target content leaked: %q", b)
	}
}

// The skills/ entry paths are checked on both sides. Directory entries get
// a real tarball, so a missing check shows as a write (RemoveAll and
// unpack of the home itself), not as a gzip error; a sentinel in the home
// must survive every refused call.
func TestSkillEntryPathsStayInTheRole(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	ctx := context.Background()
	if err := os.WriteFile(appendSystemPath(), []byte("persona\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarball, err := manifest.PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../../etc/", "../x.md", "a/b.md", "./", "../", "a/b/"} {
		if _, err := a.LoadEntry(ctx, "skills/", p); err == nil {
			t.Errorf("LoadEntry(skills/, %q) succeeded", p)
		}
		payload := []byte("x")
		if strings.HasSuffix(p, "/") {
			payload = tarball
		}
		if err := a.RestoreEntry(ctx, "skills/", p, payload); err == nil {
			t.Errorf("RestoreEntry(skills/, %q) succeeded", p)
		}
		if err := a.restoreEntrySkills(p, payload); err == nil {
			t.Errorf("restoreEntrySkills(%q) succeeded", p)
		}
	}
	if b, err := os.ReadFile(appendSystemPath()); err != nil || string(b) != "persona\n" {
		t.Fatalf("APPEND_SYSTEM.md did not survive: %q, %v", b, err)
	}
	if err := a.RestoreEntry(ctx, "skills/", "ok/", tarball); err != nil {
		t.Fatalf("a plain skill entry was refused: %v", err)
	}
}

// ClearSession removes exactly the conversation file and its prefixed
// leftovers — a leftover that is a link is removed itself, its target
// untouched — and nothing else in the home.
func TestClearSessionRemovesOnlyTheConversation(t *testing.T) {
	dshHome = t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(outside, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{conversationPath(), conversationPath() + ".ceiling-1", appendSystemPath()} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, conversationPath()+".corrupt-2"); err != nil {
		t.Fatal(err)
	}
	if err := New().ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{conversationPath(), conversationPath() + ".ceiling-1", conversationPath() + ".corrupt-2"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived ClearSession", p)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep\n" {
		t.Fatalf("a link's target was changed: %q", b)
	}
	if _, err := os.Stat(appendSystemPath()); err != nil {
		t.Fatalf("APPEND_SYSTEM.md was removed: %v", err)
	}
}

// A directory the agent put at the conversation's name (non-empty, so a
// plain remove fails) cannot make a clear fail.
func TestClearSessionWithADirectoryAtTheConversation(t *testing.T) {
	dshHome = t.TempDir()
	if err := os.MkdirAll(filepath.Join(conversationPath(), "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conversationPath(), "sub", "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().ClearSession(context.Background()); err != nil {
		t.Fatalf("ClearSession with a directory at the conversation's name: %v", err)
	}
	if _, err := os.Lstat(conversationPath()); !os.IsNotExist(err) {
		t.Fatalf("%s survived ClearSession", conversationPath())
	}
}

// The bridge runs with the agent's own HOME and an explicit DSH_HOME.
func TestBridgeEnvHomes(t *testing.T) {
	env := bridgeEnv{token: "tok"}.environ("/nm")
	want := map[string]bool{"HOME=" + privsep.AgentHome(): false, "DSH_HOME=" + dshHome: false}
	for _, kv := range env {
		if _, ok := want[kv]; ok {
			want[kv] = true
		}
	}
	for kv, ok := range want {
		if !ok {
			t.Errorf("bridge env lacks %s: %v", kv, env)
		}
	}
}

// A flat skill over its size limit is held (its committed version is kept)
// without holding the other skills; a skill directory holding a large file
// still packs.
func TestOversizedSkillHoldsOnlyItself(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	big := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, privsep.LimitTracked+1); err != nil {
			t.Fatal(err)
		}
	}
	big(filepath.Join(skillsDir(), "huge.md"))
	big(filepath.Join(skillsDir(), "bundle", "data.bin"))
	if err := os.WriteFile(filepath.Join(skillsDir(), "small.md"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	pt, err := a.EvolutionFor(context.Background(), "skills/")
	if err != nil {
		t.Fatalf("EvolutionFor(skills/) = %v; one oversized skill must not fail the role", err)
	}
	m, err := manifest.Unmarshal(pt)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]manifest.Entry{}
	for _, e := range m.Entries {
		got[e.Path] = e
	}
	if !got["huge.md"].IsHeld() {
		t.Errorf("oversized huge.md = %+v, want it held", got["huge.md"])
	}
	if e := got["small.md"]; e.IsHeld() || e.ContentHash != manifest.HashHex([]byte("s")) {
		t.Errorf("small.md = %+v, want it tracked", e)
	}
	if e, ok := got["bundle/"]; !ok || e.IsHeld() {
		t.Errorf("bundle/ = %+v, %v; want it packed", e, ok)
	}
}

// Restore makes skills/ a real directory again when the agent replaced it
// with a link, without following it.
func TestRestoreReplacesALinkedSkillsDir(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	ctx := context.Background()
	outside := t.TempDir()
	if err := os.Symlink(outside, skillsDir()); err != nil {
		t.Fatal(err)
	}
	if err := a.Restore(ctx, "skills/", nil); err != nil {
		t.Fatalf("Restore(skills/) over a link: %v", err)
	}
	if err := a.RestoreEntry(ctx, "skills/", "s.md", []byte("s")); err != nil {
		t.Fatalf("RestoreEntry: %v", err)
	}
	if fi, err := os.Lstat(skillsDir()); err != nil || !fi.IsDir() {
		t.Fatalf("skills = %v, %v; want a real directory", fi, err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("restore wrote through the link: %v", ents)
	}
}
