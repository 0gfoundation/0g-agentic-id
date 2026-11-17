package agentdata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/manifest"
	"seal-verify/internal/servicehost"
)

// fakeAgent is the agent's files as the uploader reads them, plus the chain
// pins of what was last committed.
type fakeAgent struct {
	leaf    map[string][]byte            // leaf roles
	entries map[string]map[string][]byte // manifest roles: path -> content
	dirs    map[string]map[string]bool   // manifest roles: dir entries
	chain   map[string][2]string
}

func newFake() *fakeAgent {
	return &fakeAgent{leaf: map[string][]byte{}, entries: map[string]map[string][]byte{}, dirs: map[string]map[string]bool{}, chain: map[string][2]string{}}
}

func (f *fakeAgent) EvolutionFor(_ context.Context, role string) ([]byte, error) {
	if b, ok := f.leaf[role]; ok {
		return b, nil
	}
	m := manifest.New()
	for path, b := range f.entries[role] {
		kind := manifest.EntryFile
		if f.dirs[role][path] {
			kind = manifest.EntryDir
		}
		m.Entries = append(m.Entries, manifest.Entry{Path: path, Kind: kind, ContentHash: manifest.HashHex(b), Size: len(b)})
	}
	return m.Marshal()
}

func (f *fakeAgent) LoadEntry(_ context.Context, role, path string) ([]byte, error) {
	b, ok := f.entries[role][path]
	if !ok {
		return nil, errors.New("no entry")
	}
	return b, nil
}

// commit pins the role's current content as committed.
func (f *fakeAgent) commit(t *testing.T, role string) {
	t.Helper()
	b, err := f.EvolutionFor(context.Background(), role)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	f.chain[role] = [2]string{hex.EncodeToString(sum[:]), "0xroot-" + hex.EncodeToString(sum[:4])}
}

func (f *fakeAgent) pins(role string) (string, string) { return f.chain[role][0], f.chain[role][1] }

func memoryFile(name, visibility, body string) []byte {
	v := ""
	if visibility != "" {
		v = "visibility: " + visibility + "\n"
	}
	return []byte("---\nname: " + name + "\ndescription: about " + name + "\ntype: project\nsource: owner\n" + v + "---\n\n" + body + "\n")
}

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		out[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPublicMemoryOnly(t *testing.T) {
	f := newFake()
	f.entries[RoleMemory] = map[string][]byte{
		"owner-salary.md":   memoryFile("owner-salary", "", "PRIVATE-FACT"),
		"release-freeze.md": memoryFile("release-freeze", "public", "freeze starts 2026-11-24"),
		"quoted.md":         memoryFile("quoted", `"public"`, "also public"),
		"other.md":          memoryFile("other", "private", "PRIVATE-TOO"),
		"MEMORY.md":         []byte("- [owner-salary](owner-salary.md) — PRIVATE-INDEX\n"),
	}
	f.commit(t, RoleMemory)
	base := t.TempDir()
	p := New(base, f, f.pins)
	parts, release, err := p.Parts(context.Background(), servicehost.AgentDataGrant{PublicMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	got := readTree(t, parts[0].Dir)
	if len(got) != 3 || !strings.Contains(got["release-freeze.md"], "2026-11-24") || got["quoted.md"] == "" {
		t.Fatalf("public memory view: %v", got)
	}
	if !strings.Contains(got["MEMORY.md"], "[release-freeze](release-freeze.md) — about release-freeze") || strings.Contains(got["MEMORY.md"], "PRIVATE") {
		t.Fatalf("public index: %q", got["MEMORY.md"])
	}
	v := parts[0].Version
	if v.Kind != servicehost.AgentDataPublicMemory || v.Files != 3 || v.ContentHash != f.chain[RoleMemory][0] || v.DataHash != f.chain[RoleMemory][1] {
		t.Fatalf("version %+v", v)
	}
	// No private memory is ever written below the provider's directory.
	for path, content := range readTree(t, base) {
		if strings.Contains(content, "PRIVATE") {
			t.Fatalf("private memory written to %s", path)
		}
	}
}

func TestOnlyTheCommittedVersionIsServed(t *testing.T) {
	f := newFake()
	f.leaf[RolePersona] = []byte("committed persona")
	p := New(t.TempDir(), f, f.pins)
	grant := servicehost.AgentDataGrant{Persona: true}

	// Never committed: an empty view, no chain pins.
	parts, release, err := p.Parts(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if v := parts[0].Version; v.Files != 0 || v.ContentHash != "" || v.DataHash != "" {
		t.Fatalf("never committed: %+v", v)
	}

	// Committed: built from the files that hold it.
	f.commit(t, RolePersona)
	parts, release, err = p.Parts(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	release()
	committed := parts[0].Version
	if got := readTree(t, parts[0].Dir)[RolePersona]; got != "committed persona" {
		t.Fatalf("persona %q", got)
	}

	// An uncommitted edit: the built committed version is still what jobs get.
	f.leaf[RolePersona] = []byte("uncommitted edit")
	parts, release, err = p.Parts(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if parts[0].Version != committed || readTree(t, parts[0].Dir)[RolePersona] != "committed persona" {
		t.Fatal("an uncommitted edit was served")
	}

	// A container that never built the committed version while the files
	// held it refuses rather than serve the edit.
	q := New(t.TempDir(), f, f.pins)
	if _, _, err := q.Parts(context.Background(), grant); !errors.Is(err, ErrNotReady) {
		t.Fatalf("got %v, want ErrNotReady", err)
	}
	// The next commit makes it available (Observe after the commit).
	f.commit(t, RolePersona)
	q.Observe(context.Background(), RolePersona)
	parts, release, err = q.Parts(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if readTree(t, parts[0].Dir)[RolePersona] != "uncommitted edit" {
		t.Fatal("the new commit was not served")
	}
}

func TestSkillDirectoriesAreUnpacked(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "ref"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# research"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "ref", "notes.md"), []byte("notes"), 0600); err != nil {
		t.Fatal(err)
	}
	tgz, err := manifest.PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	f := newFake()
	f.entries[RoleSkills] = map[string][]byte{"research/": tgz, "flat.md": []byte("# flat")}
	f.dirs[RoleSkills] = map[string]bool{"research/": true}
	f.commit(t, RoleSkills)
	p := New(t.TempDir(), f, f.pins)
	parts, release, err := p.Parts(context.Background(), servicehost.AgentDataGrant{Skills: true})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	got := readTree(t, parts[0].Dir)
	if got["research/SKILL.md"] != "# research" || got["research/ref/notes.md"] != "notes" || got["flat.md"] != "# flat" || parts[0].Version.Files != 3 {
		t.Fatalf("skills view: %v (%+v)", got, parts[0].Version)
	}
}

// A job's leased version stays on disk while it is copied, however many
// newer commits are built meanwhile.
func TestLeasedVersionIsKept(t *testing.T) {
	f := newFake()
	p := New(t.TempDir(), f, f.pins)
	grant := servicehost.AgentDataGrant{Persona: true}
	f.leaf[RolePersona] = []byte("v0")
	f.commit(t, RolePersona)
	parts, release, err := p.Parts(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	held := parts[0].Dir
	for i := 1; i <= keepVersions+2; i++ {
		f.leaf[RolePersona] = []byte("v" + string(rune('0'+i)))
		f.commit(t, RolePersona)
		p.Observe(context.Background(), RolePersona)
	}
	if _, err := os.Stat(held); err != nil {
		t.Fatalf("a leased version was pruned: %v", err)
	}
	release()
	f.leaf[RolePersona] = []byte("last")
	f.commit(t, RolePersona)
	p.Observe(context.Background(), RolePersona)
	if _, err := os.Stat(held); err == nil {
		t.Fatal("an old version outlived its lease and the keep window")
	}
}

func TestPublicMarker(t *testing.T) {
	for in, want := range map[string]bool{
		"---\nvisibility: public\n---\nx":       true,
		"---\nvisibility: Public\n---\nx":       true,
		"---\nvisibility: 'public'\n---\nx":     true,
		"---\nvisibility: private\n---\nx":      false,
		"---\nname: a\n---\nvisibility: public": false, // body, not front matter
		"visibility: public":                    false,
		"":                                      false,
	} {
		if Public([]byte(in)) != want {
			t.Errorf("Public(%q) = %v", in, !want)
		}
	}
}
