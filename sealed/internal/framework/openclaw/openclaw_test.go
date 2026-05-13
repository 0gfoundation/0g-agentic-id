package openclaw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStripPlatformInjection_NoMarker(t *testing.T) {
	in := []byte("# TOOLS\n\nOwner content here.\n")
	out := stripPlatformInjection(in)
	if string(out) != string(in) {
		t.Errorf("expected unchanged, got: %q", string(out))
	}
}

func TestStripPlatformInjection_FullSection(t *testing.T) {
	in := []byte("# TOOLS\n\nOwner content.\n\n" +
		platformMarkerStart + "\n" +
		"## Environment\n" +
		"injected stuff\n" +
		platformMarkerEnd + "\n")
	out := stripPlatformInjection(in)
	want := "# TOOLS\n\nOwner content."
	if string(out) != want {
		t.Errorf("strip mismatch\n want: %q\n  got: %q", want, string(out))
	}
}

func TestStripPlatformInjection_SectionWithFollowing(t *testing.T) {
	in := []byte("# TOOLS\n\n" +
		platformMarkerStart + "\n" +
		"injected\n" +
		platformMarkerEnd + "\n\n" +
		"## Owner section after\n" +
		"more owner content\n")
	out := stripPlatformInjection(in)
	want := "# TOOLS\n\n## Owner section after\nmore owner content\n"
	if string(out) != want {
		t.Errorf("strip mismatch\n want: %q\n  got: %q", want, string(out))
	}
}

func TestStripPlatformInjection_MissingEndMarker(t *testing.T) {
	in := []byte("# TOOLS\n\nOwner content.\n\n" +
		platformMarkerStart + "\n" +
		"injected stuff with no end\n")
	out := stripPlatformInjection(in)
	want := "# TOOLS\n\nOwner content."
	if string(out) != want {
		t.Errorf("truncated strip mismatch\n want: %q\n  got: %q", want, string(out))
	}
}

func TestUpsertPlatformSection_FreshFile(t *testing.T) {
	tmp := t.TempDir() + "/TOOLS.md"
	if err := upsertPlatformSection(tmp, platformCaps{publicURL: "http://8080-x.example.com:4000"}); err != nil {
		t.Fatalf("upsert err: %v", err)
	}
	body := mustRead(t, tmp)
	if !strings.Contains(body, platformMarkerStart) || !strings.Contains(body, platformMarkerEnd) {
		t.Errorf("missing markers: %q", body)
	}
	if !strings.Contains(body, "AGENT_PUBLIC_URL") {
		t.Errorf("missing AGENT_PUBLIC_URL mention: %q", body)
	}
	if !strings.Contains(body, "X-Agent-Proof") {
		t.Errorf("missing trust contract: %q", body)
	}
}

func TestUpsertPlatformSection_PreservesOwnerContent(t *testing.T) {
	tmp := t.TempDir() + "/TOOLS.md"
	owner := "# TOOLS\n\nOwner-defined tool guidance.\n"
	if err := os.WriteFile(tmp, []byte(owner), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := upsertPlatformSection(tmp, platformCaps{publicURL: "http://x.example.com"}); err != nil {
		t.Fatalf("upsert err: %v", err)
	}
	body := mustRead(t, tmp)
	if !strings.Contains(body, "Owner-defined tool guidance.") {
		t.Errorf("owner content lost: %q", body)
	}
	if !strings.Contains(body, "AGENT_PUBLIC_URL") {
		t.Errorf("platform section missing: %q", body)
	}
}

func TestUpsertPlatformSection_Idempotent(t *testing.T) {
	tmp := t.TempDir() + "/TOOLS.md"
	owner := "# TOOLS\n\nOwner content.\n"
	if err := os.WriteFile(tmp, []byte(owner), 0o644); err != nil {
		t.Fatal(err)
	}
	url := "http://8080-test.example.com"
	for i := 0; i < 3; i++ {
		if err := upsertPlatformSection(tmp, platformCaps{publicURL: url}); err != nil {
			t.Fatalf("upsert iter %d: %v", i, err)
		}
	}
	body := mustRead(t, tmp)
	if c := strings.Count(body, platformMarkerStart); c != 1 {
		t.Errorf("expected 1 markerStart, got %d in %q", c, body)
	}
	if c := strings.Count(body, platformMarkerEnd); c != 1 {
		t.Errorf("expected 1 markerEnd, got %d in %q", c, body)
	}
}

func TestUpsertPlatformSection_EmptyURLStripsSection(t *testing.T) {
	tmp := t.TempDir() + "/TOOLS.md"
	if err := upsertPlatformSection(tmp, platformCaps{publicURL: "http://x.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := upsertPlatformSection(tmp, platformCaps{}); err != nil {
		t.Fatalf("upsert with empty caps: %v", err)
	}
	body := mustRead(t, tmp)
	if strings.Contains(body, platformMarkerStart) || strings.Contains(body, "AGENT_PUBLIC_URL") {
		t.Errorf("expected platform section stripped, got: %q", body)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// ── 5-dim Restore + EvolutionFor round-trip ─────────────────────────────────

// useTempHome redirects openclawHome to t.TempDir() so disk-touching tests
// don't pollute /root/.openclaw. Restores the original value after the test.
func useTempHome(t *testing.T) {
	t.Helper()
	prev := openclawHome
	openclawHome = t.TempDir()
	t.Cleanup(func() { openclawHome = prev })
}

// dimRoundTripFixture mints a plaintext for each dim that mirrors what the
// attestor produces in production. The test then runs Restore → EvolutionFor
// → Restore (idempotent) → EvolutionFor and asserts byte-stability — which is
// what makes watcher drift detection meaningful (no phantom drift on the
// first tick or after a benign restart).
func dimRoundTripFixture(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}

	// framework: bare JSON binding
	fb := frameworkBinding{
		Name:           "openclaw",
		PackageVersion: "2026.5.6",
		SchemaVersion:  1,
	}
	b, err := json.Marshal(&fb)
	if err != nil {
		t.Fatal(err)
	}
	out["framework"] = b

	// persona: bare JSON with system_prompt + inference + ui + talk
	persona, err := json.Marshal(map[string]any{
		"system_prompt": "You are Sage. DeFi helper\n",
		"inference":     map[string]string{"provider": "anthropic", "model": "claude-opus-4-6"},
		"ui":            map[string]string{"seamColor": "#7e57c2"},
		"talk":          map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	out["persona"] = persona

	// knowledge: workspace markdown files (owner content only) + manifest.
	// tools_md must round-trip with platform section stripping handled
	// inside evoKnowledge.
	knowledge, err := json.Marshal(map[string]any{
		"memory_md": "# Memory\n",
		"dreams_md": "# Dreams\n",
		"user_md":   "# User\n",
		"agents_md": "# Agents\n",
		"tools_md":  "# Owner tools\n",
		"manifest":  map[string]any{"files": []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out["knowledge"] = knowledge

	// skills: bare JSON with all sections present (empty)
	out["skills"] = []byte(`{"plugins":{"entries":[]},"tools":{},"web":{},"approvals":{},"audio":{},"commands":{},"agent_defaults_skills":[]}`)

	// ops: bare JSON with all sections present (empty)
	out["ops"] = []byte(`{"channels":{},"mcp":{"servers":[]},"hooks":{},"cron":{"jobs":[]},"browser":{},"bindings":[],"surfaces":{},"broadcast":{},"media":{},"messages":{},"access_groups":{},"commitments":{},"secrets":{},"acp":{},"rate_limits":{},"safety":{}}`)

	return out
}

func TestAdapter_RestoreEvolutionFor_AllFiveDims_ByteStable(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}
	ctx := context.Background()
	fixture := dimRoundTripFixture(t)

	dims := []string{"framework", "persona", "knowledge", "skills", "ops"}
	for _, dim := range dims {
		if err := a.Restore(ctx, dim, fixture[dim]); err != nil {
			t.Fatalf("Restore[%s]: %v", dim, err)
		}
	}

	// EvolutionFor twice on the same in-memory state must return identical
	// bytes (deterministic packing).
	first := map[string][]byte{}
	for _, dim := range dims {
		// Skip the framework version probe — it's environment-dependent
		// (would attempt to spawn `openclaw --version` which isn't installed
		// in the test sandbox). Determinism for framework dim is exercised
		// indirectly via probeOpenclawVersion's empty-on-error fallback.
		b, err := a.EvolutionFor(ctx, dim)
		if err != nil {
			t.Fatalf("EvolutionFor[%s] (1st): %v", dim, err)
		}
		first[dim] = b
	}
	for _, dim := range dims {
		b, err := a.EvolutionFor(ctx, dim)
		if err != nil {
			t.Fatalf("EvolutionFor[%s] (2nd): %v", dim, err)
		}
		if !equalBytes(first[dim], b) {
			t.Errorf("dim=%s: EvolutionFor non-deterministic\n 1st sha=%s\n 2nd sha=%s",
				dim, sha(first[dim]), sha(b))
		}
	}

	// Round-trip: feed EvolutionFor's output back into Restore, then call
	// EvolutionFor again. Result must equal first cycle (idempotency).
	for _, dim := range dims {
		if err := a.Restore(ctx, dim, first[dim]); err != nil {
			t.Fatalf("Restore[%s] (round-trip): %v", dim, err)
		}
	}
	for _, dim := range dims {
		b, err := a.EvolutionFor(ctx, dim)
		if err != nil {
			t.Fatalf("EvolutionFor[%s] (round-trip): %v", dim, err)
		}
		if !equalBytes(first[dim], b) {
			t.Errorf("dim=%s: round-trip drift\n 1st sha=%s\n rt  sha=%s",
				dim, sha(first[dim]), sha(b))
		}
	}
}

func TestAdapter_RestoreFramework_RejectsBadSchemaVersion(t *testing.T) {
	a := &Adapter{}
	bad := []byte(`{"name":"openclaw","package_version":"2026.5.6","schema_version":99}`)
	if err := a.Restore(context.Background(), "framework", bad); err == nil {
		t.Errorf("expected error on schema_version=99, got nil")
	}
}

func TestAdapter_RestoreFramework_RejectsWrongFrameworkName(t *testing.T) {
	a := &Adapter{}
	bad := []byte(`{"name":"langchain","package_version":"x","schema_version":1}`)
	if err := a.Restore(context.Background(), "framework", bad); err == nil {
		t.Errorf("expected error on framework name mismatch, got nil")
	}
}

func TestEvoKnowledge_StripsPlatformSectionFromToolsMD(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}
	ctx := context.Background()

	// Restore knowledge with owner content only.
	knowledge := []byte(`{
		"memory_md": "",
		"dreams_md": "",
		"user_md": "",
		"agents_md": "",
		"tools_md": "# Owner tool guide\n\n- prefer the exec tool\n",
		"manifest": {"files": []}
	}`)
	if err := a.Restore(ctx, "knowledge", knowledge); err != nil {
		t.Fatalf("Restore[knowledge]: %v", err)
	}

	// Simulate spawn.go: append platform section to TOOLS.md.
	if err := upsertPlatformSection(toolsMDPath(), platformCaps{publicURL: "http://8080-x.example:4000"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Verify TOOLS.md on disk now contains BOTH owner content AND platform section.
	disk, err := os.ReadFile(toolsMDPath())
	if err != nil {
		t.Fatalf("read TOOLS.md: %v", err)
	}
	diskStr := string(disk)
	if !strings.Contains(diskStr, "# Owner tool guide") {
		t.Errorf("disk TOOLS.md lost owner content: %q", diskStr)
	}
	if !strings.Contains(diskStr, "AGENT_PUBLIC_URL") {
		t.Errorf("disk TOOLS.md missing platform section: %q", diskStr)
	}

	// EvolutionFor should round-trip ONLY owner content (platform section
	// stripped) — i.e. byte-equal to what Restore originally received.
	out, err := a.EvolutionFor(ctx, "knowledge")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	var k knowledgeConfig
	if err := json.Unmarshal(out, &k); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	// stripPlatformInjection trims trailing newlines that were added as
	// separator before the marker — owner content's prose is preserved
	// but the cosmetic trailing newline isn't. Watcher cares about
	// stable bytes across evolves, not byte-equality with attestor.
	if !strings.Contains(k.ToolsMD, "# Owner tool guide") ||
		!strings.Contains(k.ToolsMD, "prefer the exec tool") {
		t.Errorf("ToolsMD lost owner content: %q", k.ToolsMD)
	}
	if strings.Contains(k.ToolsMD, "AGENT_PUBLIC_URL") {
		t.Errorf("ToolsMD leaked platform section into iData: %q", k.ToolsMD)
	}

	// Round-trip stability: a second Restore-then-EvolutionFor of the
	// same TOOLS.md content must produce the same bytes (otherwise the
	// watcher would see phantom drift on every tick).
	roundTrip, _ := json.Marshal(map[string]any{
		"tools_md": k.ToolsMD,
		"manifest": map[string]any{"files": []any{}},
	})
	if err := a.Restore(ctx, "knowledge", roundTrip); err != nil {
		t.Fatalf("Restore round-trip: %v", err)
	}
	if err := upsertPlatformSection(toolsMDPath(), platformCaps{publicURL: "http://8080-x.example:4000"}); err != nil {
		t.Fatalf("upsert round-trip: %v", err)
	}
	out2, err := a.EvolutionFor(ctx, "knowledge")
	if err != nil {
		t.Fatalf("EvolutionFor round-trip: %v", err)
	}
	if !equalBytes(out, out2) {
		t.Errorf("knowledge dim not stable across two cycles\n first=%s\n second=%s", sha(out), sha(out2))
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}
