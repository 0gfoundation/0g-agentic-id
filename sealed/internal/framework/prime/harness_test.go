package prime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The harness-state canonicalization is this adapter's identity anchor; every
// case below is a phantom-drift or privacy bug if it regresses.

func TestCanonicalizeHarness_DropsRefinementsAndLocalScope(t *testing.T) {
	raw := []byte(`{
	  "schema": 1,
	  "entries": {
	    "prompt": {
	      "keep": {"id": "keep", "scope": "global", "title": "kept"},
	      "drop": {"id": "drop", "scope": "local", "title": "mid-task edit"}
	    },
	    "memory": {
	      "l": {"id": "l", "scope": "local", "title": "session note"}
	    }
	  },
	  "refinements": [{"event": "refine", "note": "task transcript fragment"}]
	}`)

	got, err := canonicalizeHarness(raw)
	if err != nil {
		t.Fatalf("canonicalizeHarness: %v", err)
	}
	want := `{"entries":{"prompt":{"keep":{"id":"keep","scope":"global","title":"kept"}}},"schema":1}`
	if string(got) != want {
		t.Errorf("canonical form:\n got = %s\nwant = %s", got, want)
	}
}

// An all-local state has no durable identity, so it must produce NO chain
// entry — otherwise a fresh agent's first mid-task refine lands on chain.
func TestCanonicalizeHarness_AllLocalIsNil(t *testing.T) {
	raw := []byte(`{"schema":1,"entries":{"prompt":{"a":{"id":"a","scope":"local"}}},"refinements":[]}`)
	got, err := canonicalizeHarness(raw)
	if err != nil {
		t.Fatalf("canonicalizeHarness: %v", err)
	}
	if got != nil {
		t.Errorf("all-local state should canonicalize to nil, got %s", got)
	}
}

// The framework writes with json.dump(indent=2) and does NOT sort keys, so two
// semantically identical files can differ byte-wise. Canonicalization must
// erase that difference or every restart re-uploads the role.
func TestCanonicalizeHarness_KeyOrderIndependent(t *testing.T) {
	a := []byte(`{"schema":1,"entries":{"prompt":{"p":{"id":"p","scope":"global","title":"t","version":3}}}}`)
	b := []byte(`{"entries":{"prompt":{"p":{"version":3,"title":"t","scope":"global","id":"p"}}},"schema":1}`)

	ca, err := canonicalizeHarness(a)
	if err != nil {
		t.Fatalf("canonicalizeHarness(a): %v", err)
	}
	cb, err := canonicalizeHarness(b)
	if err != nil {
		t.Fatalf("canonicalizeHarness(b): %v", err)
	}
	if string(ca) != string(cb) {
		t.Errorf("key order leaked into canonical form:\n a = %s\n b = %s", ca, cb)
	}
}

// Large integers must not round-trip through float64 into exponent notation —
// that would silently rewrite an agent's own state on the way to chain.
func TestCanonicalizeHarness_PreservesLargeNumbers(t *testing.T) {
	raw := []byte(`{"schema":1,"entries":{"memory":{"m":{"id":"m","scope":"global","ts":1754870400000}}}}`)
	got, err := canonicalizeHarness(raw)
	if err != nil {
		t.Fatalf("canonicalizeHarness: %v", err)
	}
	if want := `"ts":1754870400000`; !contains(string(got), want) {
		t.Errorf("large int mangled: got %s, want it to contain %s", got, want)
	}
}

// Restore must not destroy the local refinements log (untracked runtime audit
// data that has to survive a Restore), while still replacing the tracked half.
func TestRestoreHarnessState_PreservesRefinements(t *testing.T) {
	primeHome = t.TempDir()
	a := New()

	if err := os.MkdirAll(harnessStateDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"schema":1,"entries":{"prompt":{"old":{"id":"old","scope":"global"}}},"refinements":[{"event":"refine","n":1}]}`
	if err := os.WriteFile(harnessStatePath(), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	incoming := []byte(`{"entries":{"memory":{"new":{"id":"new","scope":"global"}}},"schema":1}`)
	if err := a.restoreHarnessState(incoming); err != nil {
		t.Fatalf("restoreHarnessState: %v", err)
	}

	onDisk, err := os.ReadFile(harnessStatePath())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Entries     map[string]map[string]map[string]any `json:"entries"`
		Refinements []map[string]any                     `json:"refinements"`
	}
	if err := json.Unmarshal(onDisk, &parsed); err != nil {
		t.Fatalf("parse written state: %v", err)
	}
	if len(parsed.Refinements) != 1 {
		t.Errorf("refinements log not preserved: %v", parsed.Refinements)
	}
	if _, ok := parsed.Entries["memory"]["new"]; !ok {
		t.Errorf("restored entry missing: %v", parsed.Entries)
	}
	if _, ok := parsed.Entries["prompt"]["old"]; ok {
		t.Errorf("stale tracked entry survived Restore: %v", parsed.Entries)
	}

	// And the round trip: what we just restored must read back identically.
	got, err := a.evoHarnessState()
	if err != nil {
		t.Fatalf("evoHarnessState: %v", err)
	}
	if string(got) != string(incoming) {
		t.Errorf("round-trip broken:\n got = %s\nwant = %s", got, incoming)
	}
}

// A binding naming another framework must fail loud rather than boot and forge
// this agent's identity (FRAMEWORK_ADAPTER.md §3).
func TestRestoreFramework_RejectsForeignBinding(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	err := a.restoreFramework([]byte(`{"name":"openclaw","package_version":"1.0.0","schema_version":1}`))
	if err == nil {
		t.Fatal("foreign binding accepted; want a loud failure")
	}
}

// A version-less binding (what attestor mints) resolves to whitelistMax, and
// an unvalidated pin is coerced rather than installed.
func TestRestoreFramework_VersionResolution(t *testing.T) {
	primeHome = t.TempDir()
	a := New()

	for _, tc := range []struct{ name, in string }{
		{"version-less", `{"name":"prime-agent","schema_version":1}`},
		{"unvalidated", `{"name":"prime-agent","package_version":"0.1.0","schema_version":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := a.restoreFramework([]byte(tc.in)); err != nil {
				t.Fatalf("restoreFramework: %v", err)
			}
			got, err := a.EvolutionFor(context.Background(), "framework")
			if err != nil {
				t.Fatalf("EvolutionFor(framework): %v", err)
			}
			var b frameworkBinding
			if err := json.Unmarshal(got, &b); err != nil {
				t.Fatal(err)
			}
			if b.PackageVersion != whitelistMax() {
				t.Errorf("package_version = %q, want whitelistMax %q", b.PackageVersion, whitelistMax())
			}
		})
	}
}

// HandleLegacy("persona") must land the system prompt in APPEND_SYSTEM.md and
// record the inference pin, and must never error on an unknown role.
func TestHandleLegacyPersona(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	ctx := context.Background()

	seed := []byte(`{"system_prompt":"You are Ada. A careful assistant.\n","inference":{"provider":"0g-compute","model":"0gm-1.0-35b-a3b"}}`)
	if err := a.HandleLegacy(ctx, "persona", seed); err != nil {
		t.Fatalf("HandleLegacy(persona): %v", err)
	}

	content, err := os.ReadFile(appendSystemPath())
	if err != nil {
		t.Fatalf("read %s: %v", appendSystemPath(), err)
	}
	if string(content) != "You are Ada. A careful assistant.\n" {
		t.Errorf("persona not ingested: %q", content)
	}
	if a.personaProvider != "0g-compute" || a.personaModel != "0gm-1.0-35b-a3b" {
		t.Errorf("inference pin not recorded: %s/%s", a.personaProvider, a.personaModel)
	}

	if err := a.HandleLegacy(ctx, "totally-unknown", []byte("x")); err != nil {
		t.Errorf("HandleLegacy(unknown) = %v, want nil (log-and-ignore)", err)
	}
	// Idempotent: re-ingesting the same seed changes nothing.
	if err := a.HandleLegacy(ctx, "persona", seed); err != nil {
		t.Fatalf("HandleLegacy(persona) second call: %v", err)
	}
	again, err := os.ReadFile(appendSystemPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(content) {
		t.Errorf("persona ingestion not idempotent")
	}
}

// The skills role must exclude dotfiles/dot-dirs so a stray cache directory
// never becomes a chain entry.
func TestEvoSkills_SkipsDotDirs(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	for _, d := range []string{"real", ".cache"} {
		if err := os.MkdirAll(filepath.Join(skillsDir(), d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(skillsDir(), d, "f.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := a.evoSkills()
	if err != nil {
		t.Fatalf("evoSkills: %v", err)
	}
	if contains(string(got), ".cache") {
		t.Errorf("dot-dir tracked: %s", got)
	}
	if !contains(string(got), "real/") {
		t.Errorf("real skill dir missing: %s", got)
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
