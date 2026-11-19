package scrub

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
)

const secret = "ghp_the_value_itself_0123456789"

// values replaces secret with its placeholder.
type values struct {
	n   int
	gen uint64
}

func (v *values) Len() int           { return v.n }
func (v *values) Generation() uint64 { return v.gen }
func (v *values) Scrub(b []byte) []byte {
	if !bytes.Contains(b, []byte(secret)) {
		return b
	}
	return bytes.ReplaceAll(b, []byte(secret), []byte("[[credential:github]]"))
}

// fakeFW serves a leaf role "notes" and a manifest role "skills".
type fakeFW struct {
	framework.Framework
	notes   []byte
	entries map[string][]byte // path → content (dir entries: archives)
	loads   int
}

func (f *fakeFW) Roles() []framework.RoleSpec {
	return []framework.RoleSpec{{Name: "notes", Shape: framework.Leaf}, {Name: "skills", Shape: framework.DirectoryManifest}}
}

func (f *fakeFW) EvolutionFor(_ context.Context, role string) ([]byte, error) {
	if role == "notes" {
		return f.notes, nil
	}
	m := manifest.New()
	for p, c := range f.entries {
		kind := manifest.EntryFile
		if strings.HasSuffix(p, "/") {
			kind = manifest.EntryDir
		}
		m.Entries = append(m.Entries, manifest.Entry{Path: p, Kind: kind, ContentHash: manifest.HashHex(c), Size: len(c)})
	}
	m.Entries = append(m.Entries, manifest.Held("big", manifest.EntryFile))
	return m.Marshal()
}

func (f *fakeFW) LoadEntry(_ context.Context, _ string, path string) ([]byte, error) {
	f.loads++
	return f.entries[path], nil
}

func TestLeafRoleIsScrubbed(t *testing.T) {
	fw := &fakeFW{notes: []byte("token: " + secret + "\n")}
	v := &values{n: 1, gen: 1}
	got, err := Wrap(fw, v).EvolutionFor(context.Background(), "notes")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "token: [[credential:github]]\n" {
		t.Fatalf("got %q", got)
	}
	v.n = 0
	got, _ = Wrap(fw, v).EvolutionFor(context.Background(), "notes")
	if !bytes.Equal(got, fw.notes) {
		t.Fatal("content changed with no values held")
	}
}

func TestManifestEntriesCarryScrubbedHashes(t *testing.T) {
	fw := &fakeFW{entries: map[string][]byte{
		"plain.md": []byte("nothing here"),
		"leak.md":  []byte("export GH=" + secret),
	}}
	v := &values{n: 1, gen: 1}
	a := Wrap(fw, v)
	ctx := context.Background()

	out, err := a.EvolutionFor(ctx, "skills")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Unmarshal(out)
	if err != nil {
		t.Fatal(err)
	}
	leak, _ := a.LoadEntry(ctx, "skills", "leak.md")
	if bytes.Contains(leak, []byte(secret)) {
		t.Fatal("LoadEntry returned the value")
	}
	e := m.EntryByPath("leak.md")
	if e.ContentHash != manifest.HashHex(leak) || e.Size != len(leak) {
		t.Fatalf("manifest entry %+v does not describe the uploaded bytes", *e)
	}
	if p := m.EntryByPath("plain.md"); p.ContentHash != manifest.HashHex(fw.entries["plain.md"]) {
		t.Fatal("an entry with nothing to scrub changed its hash")
	}
	if !m.EntryByPath("big").IsHeld() {
		t.Fatal("a held entry was touched")
	}

	// The next pass reads nothing again, and returns the same bytes: no drift.
	loads := fw.loads
	again, _ := a.EvolutionFor(ctx, "skills")
	if fw.loads != loads || !bytes.Equal(again, out) {
		t.Fatalf("second pass read %d entries again or changed (%v)", fw.loads-loads, !bytes.Equal(again, out))
	}
	// New values: every entry is looked at again.
	v.gen++
	_, _ = a.EvolutionFor(ctx, "skills")
	if fw.loads == loads {
		t.Fatal("a change in values did not rescan")
	}
}

func TestDirectoryEntryArchiveIsScrubbed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("curl -H 'Authorization: Bearer "+secret+"'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	tgz, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fw := &fakeFW{entries: map[string][]byte{"tool/": tgz}}
	a := Wrap(fw, &values{n: 1, gen: 1})
	ctx := context.Background()

	out, _ := a.EvolutionFor(ctx, "skills")
	m, _ := manifest.Unmarshal(out)
	archive, err := a.LoadEntry(ctx, "skills", "tool/")
	if err != nil {
		t.Fatal(err)
	}
	if m.EntryByPath("tool/").ContentHash != manifest.HashHex(archive) {
		t.Fatal("manifest hash does not describe the uploaded archive")
	}
	files := untar(t, archive)
	if strings.Contains(files["run.sh"], secret) || !strings.Contains(files["run.sh"], "[[credential:github]]") || files["README"] != "hello" {
		t.Fatalf("archive content %v", files)
	}
	// Deterministic: the same archive scrubs to the same bytes.
	second, _ := a.LoadEntry(ctx, "skills", "tool/")
	if !bytes.Equal(second, archive) {
		t.Fatal("scrubbing the same archive twice gave different bytes")
	}
	// An archive with nothing to scrub is returned as it is.
	clean, _ := manifest.ScrubArchive(tgz, func(b []byte) []byte { return b })
	if !bytes.Equal(clean, tgz) {
		t.Fatal("an archive with nothing to scrub changed")
	}
}

func untar(t *testing.T, tgz []byte) map[string]string {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gr)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
}
