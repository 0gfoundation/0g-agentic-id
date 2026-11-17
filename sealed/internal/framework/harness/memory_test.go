package harness

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
)

func TestMemoryRoleDeclared(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	found := false
	for _, r := range a.Roles() {
		if r.Name == "memory/" {
			found = true
			if r.Shape != framework.DirectoryManifest {
				t.Fatalf("memory/ shape = %v, want DirectoryManifest", r.Shape)
			}
		}
	}
	if !found {
		t.Fatal("memory/ is not a declared role")
	}
	empty, err := manifest.New().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Defaults("memory/"); !bytes.Equal(got, empty) {
		t.Fatalf("Defaults(memory/) = %q, want the empty manifest %q", got, empty)
	}
	if !a.KeepsUncommitted("memory/") {
		t.Fatal("memory/ is the agent's own writing: a boot of the same container must keep its uncommitted changes")
	}
}

// An agent minted before the role existed has no memory/ entry on chain:
// bootstrap restores it from nil, which lands an empty directory, and the
// role's evolution then equals its default, so nothing drifts until the agent
// writes a memory.
func TestRestoreOfAnAgentWithoutTheMemoryRole(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	ctx := context.Background()
	if err := a.Restore(ctx, "memory/", nil); err != nil {
		t.Fatalf("Restore(memory/, nil): %v", err)
	}
	if fi, err := os.Stat(memoryDir()); err != nil || !fi.IsDir() {
		t.Fatalf("memory/ not created: %v", err)
	}
	got, err := a.EvolutionFor(ctx, "memory/")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, a.Defaults("memory/")) {
		t.Fatalf("EvolutionFor(memory/) after an empty restore = %q, want the default", got)
	}
}

// Only the flat, non-empty Markdown files directly in memory/ are memories.
func TestMemoryTracksFlatMarkdownOnly(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	ctx := context.Background()
	if err := a.Restore(ctx, "memory/", nil); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(memoryDir(), name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(memoryDir(), name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("MEMORY.md", "- [Owner](owner.md) — who the owner is\n")
	write("owner.md", "---\nname: owner\ndescription: who the owner is\ntype: user\nsource: owner\n---\n\nPrefers short answers.\n")
	write("empty.md", "")
	write(".draft.md", "not yet\n")
	write("notes.txt", "not markdown\n")
	write("sub/nested.md", "not flat\n")
	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(memoryDir(), "link.md")); err != nil {
		t.Fatal(err)
	}

	pt, err := a.EvolutionFor(ctx, "memory/")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Unmarshal(pt)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range m.Entries {
		paths = append(paths, e.Path)
	}
	if len(paths) != 2 || paths[0] != "MEMORY.md" || paths[1] != "owner.md" {
		t.Fatalf("tracked %v, want [MEMORY.md owner.md]", paths)
	}
	b, err := a.LoadEntry(ctx, "memory/", "owner.md")
	if err != nil || !bytes.Contains(b, []byte("Prefers short answers.")) {
		t.Fatalf("LoadEntry(memory/, owner.md) = %q, %v", b, err)
	}
}

// Entry paths are checked on both sides; a sentinel in the home survives
// every refused call.
func TestMemoryEntryPathsStayInTheRole(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	ctx := context.Background()
	if err := os.WriteFile(appendSystemPath(), []byte("persona\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../APPEND_SYSTEM.md", "../x.md", "a/b.md", "x/", "../", "notes.txt", ".hidden.md", ""} {
		if _, err := a.LoadEntry(ctx, "memory/", p); err == nil {
			t.Errorf("LoadEntry(memory/, %q) succeeded", p)
		}
		if err := a.RestoreEntry(ctx, "memory/", p, []byte("x")); err == nil {
			t.Errorf("RestoreEntry(memory/, %q) succeeded", p)
		}
	}
	if b, err := os.ReadFile(appendSystemPath()); err != nil || string(b) != "persona\n" {
		t.Fatalf("APPEND_SYSTEM.md did not survive: %q, %v", b, err)
	}
	if err := a.RestoreEntry(ctx, "memory/", "owner.md", []byte("remembered\n")); err != nil {
		t.Fatalf("a plain memory entry was refused: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(memoryDir(), "owner.md")); err != nil || string(b) != "remembered\n" {
		t.Fatalf("restored memory = %q, %v", b, err)
	}
}

// Restore makes memory/ a real directory again when the agent replaced it
// with a link, and an entry then lands inside the home, not at the target.
func TestRestoreReplacesALinkedMemoryDir(t *testing.T) {
	dshHome = t.TempDir()
	a := New()
	ctx := context.Background()
	target := t.TempDir()
	if err := os.Symlink(target, memoryDir()); err != nil {
		t.Fatal(err)
	}
	if err := a.Restore(ctx, "memory/", nil); err != nil {
		t.Fatalf("Restore(memory/) over a link: %v", err)
	}
	if err := a.RestoreEntry(ctx, "memory/", "m.md", []byte("m")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "m.md")); err == nil {
		t.Fatal("the entry was written through the link")
	}
	if fi, err := os.Lstat(memoryDir()); err != nil || !fi.IsDir() {
		t.Fatalf("memory/ is not a real directory: %v", err)
	}
}
