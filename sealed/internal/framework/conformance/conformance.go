// Package conformance is an executable test harness for the invariants
// every framework adapter must satisfy (FRAMEWORK_ADAPTER.md §9). Each
// adapter package runs it from its own test file:
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, conformance.Config{
//	        New: func(t *testing.T) framework.Framework {
//	            adapterHome = t.TempDir() // redirect disk roots
//	            return New()
//	        },
//	        Fixtures: []conformance.Fixture{ … },
//	    })
//	}
//
// The harness exists because these invariants used to live only in prose:
// the first adapter (openclaw) grew its round-trip discipline through a
// series of phantom-drift incidents, and the second adapter (claudecode)
// had no way to know it was safe short of re-living them. Violations the
// watcher would turn into infinite re-upload loops in production fail
// here as plain test assertions.
package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
)

// Fixture supplies per-role sample content for the round-trip checks.
// Exactly one content field group applies, matched to the role's Shape:
//
//   - Leaf roles: Leaf holds the canonical plaintext. It must already be
//     in the adapter's canonical encoding (compact JSON, sorted keys, …)
//     because the harness asserts EvolutionFor returns it byte-identical.
//   - DirectoryManifest roles: Files maps entry path → file content;
//     Dirs maps entry slug (no trailing slash) → {relative path → content}
//     for tar.gz dir entries. The harness computes the expected manifest.
//
// Roles without a fixture are still exercised by the Defaults round-trip.
type Fixture struct {
	Role  string
	Leaf  []byte
	Files map[string][]byte
	Dirs  map[string]map[string][]byte
}

// Config wires an adapter into the harness.
type Config struct {
	// New returns a fresh adapter whose disk roots are redirected into
	// t.TempDir() (and whose external probes are stubbed — a live
	// `claude --version` on the test machine must not leak into results).
	// Called once per subtest; each call must yield fully isolated state.
	New func(t *testing.T) framework.Framework

	// Fixtures provide round-trip content per role. Optional but strongly
	// recommended for every declared role.
	Fixtures []Fixture
}

// Run executes the conformance suite as subtests.
func Run(t *testing.T, cfg Config) {
	if cfg.New == nil {
		t.Fatal("conformance: Config.New is required")
	}
	t.Run("RolesSanity", func(t *testing.T) { rolesSanity(t, cfg) })
	t.Run("DefaultsRoundTrip", func(t *testing.T) { defaultsRoundTrip(t, cfg) })
	t.Run("FixtureRoundTrip", func(t *testing.T) { fixtureRoundTrip(t, cfg, false) })
	t.Run("RestoreCommutativity", func(t *testing.T) { fixtureRoundTrip(t, cfg, true) })
	t.Run("UnknownRoleContract", func(t *testing.T) { unknownRoleContract(t, cfg) })
}

// rolesSanity checks the declared role set's structural rules: unique
// names, the protocol-reserved "framework" leaf present, and the
// trailing-slash naming convention matching each role's Shape.
func rolesSanity(t *testing.T, cfg Config) {
	fw := cfg.New(t)
	roles := fw.Roles()
	if len(roles) == 0 {
		t.Fatal("Roles() returned no roles")
	}
	seen := map[string]bool{}
	hasFramework := false
	for _, r := range roles {
		if seen[r.Name] {
			t.Errorf("duplicate role %q", r.Name)
		}
		seen[r.Name] = true
		if r.Name == "framework" {
			hasFramework = true
			if r.Shape != framework.Leaf {
				t.Errorf("reserved role \"framework\" must be Leaf, got %q", r.Shape)
			}
		}
		switch r.Shape {
		case framework.Leaf:
			if r.Name[len(r.Name)-1] == '/' {
				t.Errorf("leaf role %q must not end with '/'", r.Name)
			}
		case framework.DirectoryManifest:
			if r.Name[len(r.Name)-1] != '/' {
				t.Errorf("manifest role %q must end with '/'", r.Name)
			}
		default:
			t.Errorf("role %q has unknown shape %q", r.Name, r.Shape)
		}
	}
	if !hasFramework {
		t.Error("role set must include the protocol-reserved \"framework\" leaf")
	}
}

// defaultsRoundTrip asserts the FRAMEWORK_ADAPTER.md §3.1 invariant:
// Restore(role, nil) followed by EvolutionFor must reproduce
// Defaults(role) byte-identically for every declared role — otherwise a
// fresh agent phantom-drifts on its very first watcher tick.
func defaultsRoundTrip(t *testing.T, cfg Config) {
	ctx := context.Background()
	fw := cfg.New(t)
	for _, r := range fw.Roles() {
		if err := fw.Restore(ctx, r.Name, nil); err != nil {
			t.Fatalf("Restore(%q, nil): %v", r.Name, err)
		}
	}
	for _, r := range fw.Roles() {
		got, err := fw.EvolutionFor(ctx, r.Name)
		if err != nil {
			t.Fatalf("EvolutionFor(%q): %v", r.Name, err)
		}
		want := fw.Defaults(r.Name)
		if !bytes.Equal(got, want) {
			t.Errorf("defaults round-trip broken for %q:\n  Restore(nil)→EvolutionFor = %s\n  Defaults               = %s", r.Name, got, want)
		}
	}
}

// fixtureRoundTrip restores every fixture (bootstrap order: parent
// manifest, then entries), then asserts per role:
//
//  1. EvolutionFor reproduces the canonical plaintext byte-identically
//  2. a second EvolutionFor call is byte-identical (determinism)
//  3. every manifest entry's LoadEntry hashes to the manifest-declared
//     content_hash (the uploader's assumption)
//
// With reversed=true the fixtures (and each fixture's entries) restore in
// reverse order, asserting Restore commutativity.
func fixtureRoundTrip(t *testing.T, cfg Config, reversed bool) {
	if len(cfg.Fixtures) == 0 {
		t.Skip("no fixtures provided")
	}
	ctx := context.Background()
	fw := cfg.New(t)
	shapes := map[string]framework.Shape{}
	for _, r := range fw.Roles() {
		shapes[r.Name] = r.Shape
	}

	type prepared struct {
		fixture  Fixture
		expected []byte            // canonical plaintext EvolutionFor must return
		entries  map[string][]byte // entry path → plaintext (manifest roles)
	}
	preps := make([]prepared, 0, len(cfg.Fixtures))
	for _, f := range cfg.Fixtures {
		shape, ok := shapes[f.Role]
		if !ok {
			t.Fatalf("fixture role %q not in Roles()", f.Role)
		}
		p := prepared{fixture: f}
		switch shape {
		case framework.Leaf:
			if f.Leaf == nil {
				t.Fatalf("fixture for leaf role %q must set Leaf", f.Role)
			}
			p.expected = f.Leaf
		case framework.DirectoryManifest:
			var err error
			p.expected, p.entries, err = buildManifestFixture(t, f)
			if err != nil {
				t.Fatalf("build manifest fixture for %q: %v", f.Role, err)
			}
		}
		preps = append(preps, p)
	}
	if reversed {
		for i, j := 0, len(preps)-1; i < j; i, j = i+1, j-1 {
			preps[i], preps[j] = preps[j], preps[i]
		}
	}

	// Restore phase, bootstrap order per role: parent manifest first,
	// entries after.
	for _, p := range preps {
		if err := fw.Restore(ctx, p.fixture.Role, p.expected); err != nil {
			t.Fatalf("Restore(%q): %v", p.fixture.Role, err)
		}
		paths := sortedKeys(p.entries)
		if reversed {
			reverse(paths)
		}
		for _, path := range paths {
			if err := fw.RestoreEntry(ctx, p.fixture.Role, path, p.entries[path]); err != nil {
				t.Fatalf("RestoreEntry(%q, %q): %v", p.fixture.Role, path, err)
			}
		}
	}
	// Roles without fixtures still get their defaults so EvolutionFor has
	// composed state to read.
	fixtureRoles := map[string]bool{}
	for _, p := range preps {
		fixtureRoles[p.fixture.Role] = true
	}
	for _, r := range fw.Roles() {
		if !fixtureRoles[r.Name] {
			if err := fw.Restore(ctx, r.Name, nil); err != nil {
				t.Fatalf("Restore(%q, nil): %v", r.Name, err)
			}
		}
	}

	// Verify phase.
	for _, p := range preps {
		got, err := fw.EvolutionFor(ctx, p.fixture.Role)
		if err != nil {
			t.Fatalf("EvolutionFor(%q): %v", p.fixture.Role, err)
		}
		if !bytes.Equal(got, p.expected) {
			t.Errorf("round-trip broken for %q:\n  got  = %s\n  want = %s", p.fixture.Role, got, p.expected)
			continue
		}
		again, err := fw.EvolutionFor(ctx, p.fixture.Role)
		if err != nil {
			t.Fatalf("EvolutionFor(%q) second call: %v", p.fixture.Role, err)
		}
		if !bytes.Equal(got, again) {
			t.Errorf("EvolutionFor(%q) is nondeterministic across consecutive calls", p.fixture.Role)
		}
		if p.entries == nil {
			continue
		}
		m, err := manifest.Unmarshal(got)
		if err != nil {
			t.Fatalf("parse EvolutionFor(%q) manifest: %v", p.fixture.Role, err)
		}
		for _, e := range m.Entries {
			content, err := fw.LoadEntry(ctx, p.fixture.Role, e.Path)
			if err != nil {
				t.Errorf("LoadEntry(%q, %q): %v", p.fixture.Role, e.Path, err)
				continue
			}
			if h := manifest.HashHex(content); h != e.ContentHash {
				t.Errorf("LoadEntry(%q, %q) hashes to %s; manifest declares %s — uploads would loop",
					p.fixture.Role, e.Path, h, e.ContentHash)
			}
		}
	}
}

// unknownRoleContract asserts the error-handling edges: EvolutionFor /
// LoadEntry / RestoreEntry on an undeclared role return ErrUnsupportedDim,
// and HandleLegacy on an unknown legacy role logs-and-ignores (nil).
func unknownRoleContract(t *testing.T, cfg Config) {
	ctx := context.Background()
	fw := cfg.New(t)
	const bogus = "__conformance_no_such_role__"

	if _, err := fw.EvolutionFor(ctx, bogus); !errors.Is(err, framework.ErrUnsupportedDim) {
		t.Errorf("EvolutionFor(unknown role) = %v; want ErrUnsupportedDim", err)
	}
	if _, err := fw.LoadEntry(ctx, bogus, "x"); !errors.Is(err, framework.ErrUnsupportedDim) {
		t.Errorf("LoadEntry(unknown role) = %v; want ErrUnsupportedDim", err)
	}
	if err := fw.RestoreEntry(ctx, bogus, "x", []byte("y")); !errors.Is(err, framework.ErrUnsupportedDim) {
		t.Errorf("RestoreEntry(unknown role) = %v; want ErrUnsupportedDim", err)
	}
	if err := fw.HandleLegacy(ctx, bogus, []byte("legacy")); err != nil {
		t.Errorf("HandleLegacy(unknown role) = %v; want nil (log-and-ignore)", err)
	}
}

// buildManifestFixture materialises a manifest fixture: file entries
// verbatim, dir entries via a temp source tree packed with the same
// deterministic tar the adapter must use. Returns the canonical
// (empty-ptr) manifest plaintext and the per-entry plaintext map.
func buildManifestFixture(t *testing.T, f Fixture) ([]byte, map[string][]byte, error) {
	m := manifest.New()
	entries := map[string][]byte{}

	for _, path := range sortedKeys(f.Files) {
		content := f.Files[path]
		if len(content) == 0 {
			return nil, nil, fmt.Errorf("file entry %q: empty content is untracked by convention; use non-empty fixture content", path)
		}
		m.Entries = append(m.Entries, manifest.Entry{
			Path:        path,
			Kind:        manifest.EntryFile,
			ContentHash: manifest.HashHex(content),
			Size:        len(content),
		})
		entries[path] = content
	}
	for _, slug := range sortedKeys(f.Dirs) {
		src := filepath.Join(t.TempDir(), slug)
		for _, rel := range sortedKeys(f.Dirs[slug]) {
			full := filepath.Join(src, rel)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(full, f.Dirs[slug][rel], 0o644); err != nil {
				return nil, nil, err
			}
		}
		tarBytes, err := manifest.PackDir(src)
		if err != nil {
			return nil, nil, err
		}
		m.Entries = append(m.Entries, manifest.Entry{
			Path:        slug + "/",
			Kind:        manifest.EntryDir,
			ContentHash: manifest.HashHex(tarBytes),
			Size:        len(tarBytes),
		})
		entries[slug+"/"] = tarBytes
	}

	plaintext, err := m.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return plaintext, entries, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
