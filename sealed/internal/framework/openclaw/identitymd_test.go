package openclaw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/platform"
)

const testAgentSeal = "0x1234567890abcdef1234567890abcdef12345678"

// testIdentitySection builds a platform identity section for tests,
// mirroring what spawn.go does at runtime.
func testIdentitySection(agentSeal string) string {
	rs := platform.RuntimeSnapshot{AgentSeal: agentSeal}
	return platform.Build(rs).Identity
}

// ── upsertIdentityMD ───────────────────────────────────────────────────────

func TestUpsertIdentityMD_FreshFileSeedsHeader(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "IDENTITY.md")
	if err := upsertIdentityMD(tmp, testIdentitySection(testAgentSeal)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	body := mustRead(t, tmp)
	// Top-level heading must precede the marker block so openclaw's
	// identity merger inserts owner fields outside our markers.
	headingIdx := strings.Index(body, "# IDENTITY.md - Agent Identity")
	markerIdx := strings.Index(body, platformMarkerStart)
	if headingIdx < 0 {
		t.Errorf("seed heading missing: %q", body)
	}
	if markerIdx < 0 {
		t.Errorf("marker block missing: %q", body)
	}
	if headingIdx >= markerIdx {
		t.Errorf("seed heading (%d) must come before marker (%d): %q", headingIdx, markerIdx, body)
	}
	// Key facts must be present so the LLM gets the runtime identity claim.
	for _, want := range []string{"agentSeal", "AGENT_SEAL", testAgentSeal, "TOOLS.md", "SOUL.md"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing token %q in IDENTITY.md body: %q", want, body)
		}
	}
}

func TestUpsertIdentityMD_PreservesOwnerIdentityFields(t *testing.T) {
	// Simulate openclaw having injected owner-set identity fields between
	// the heading and our marker block (the layout the seed enables).
	tmp := filepath.Join(t.TempDir(), "IDENTITY.md")
	owner := "# IDENTITY.md - Agent Identity\n\n- Name: Sage\n- Vibe: friendly\n"
	if err := os.WriteFile(tmp, []byte(owner), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := upsertIdentityMD(tmp, testIdentitySection(testAgentSeal)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	body := mustRead(t, tmp)
	if !strings.Contains(body, "- Name: Sage") || !strings.Contains(body, "- Vibe: friendly") {
		t.Errorf("owner identity fields lost: %q", body)
	}
	if !strings.Contains(body, testAgentSeal) {
		t.Errorf("agentSeal not injected: %q", body)
	}
	// Strip our markers → owner content must round-trip byte-equal.
	stripped := string(stripPlatformInjection([]byte(body)))
	if !strings.Contains(stripped, "- Name: Sage") || !strings.Contains(stripped, "- Vibe: friendly") {
		t.Errorf("owner fields not preserved across strip: %q", stripped)
	}
	if strings.Contains(stripped, testAgentSeal) {
		t.Errorf("sealed content leaked into stripped output: %q", stripped)
	}
}

func TestUpsertIdentityMD_Idempotent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "IDENTITY.md")
	section := testIdentitySection(testAgentSeal)
	for i := 0; i < 3; i++ {
		if err := upsertIdentityMD(tmp, section); err != nil {
			t.Fatalf("upsert iter %d: %v", i, err)
		}
	}
	body := mustRead(t, tmp)
	if c := strings.Count(body, platformMarkerStart); c != 1 {
		t.Errorf("expected 1 markerStart, got %d: %q", c, body)
	}
	if c := strings.Count(body, platformMarkerEnd); c != 1 {
		t.Errorf("expected 1 markerEnd, got %d: %q", c, body)
	}
	if c := strings.Count(body, "# IDENTITY.md - Agent Identity"); c != 1 {
		t.Errorf("expected 1 seed heading, got %d: %q", c, body)
	}
}

func TestUpsertIdentityMD_EmptySectionStripsSection(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "IDENTITY.md")
	if err := upsertIdentityMD(tmp, testIdentitySection(testAgentSeal)); err != nil {
		t.Fatal(err)
	}
	if err := upsertIdentityMD(tmp, ""); err != nil {
		t.Fatalf("strip upsert: %v", err)
	}
	body := mustRead(t, tmp)
	if strings.Contains(body, platformMarkerStart) {
		t.Errorf("expected marker stripped: %q", body)
	}
	if strings.Contains(body, testAgentSeal) {
		t.Errorf("expected sealed content gone: %q", body)
	}
	// Seed heading should stay — a stripped IDENTITY.md with just the
	// heading is still well-formed for openclaw.
	if !strings.Contains(body, "# IDENTITY.md - Agent Identity") {
		t.Errorf("seed heading lost after strip: %q", body)
	}
}

// ── platform.Build identity ────────────────────────────────────────────────

func TestPlatformBuildIdentity_ContainsRequiredTokens(t *testing.T) {
	body := testIdentitySection(testAgentSeal)
	// Facts the LLM must see verbatim.
	for _, want := range []string{
		"agentSeal",
		"AGENT_SEAL",
		testAgentSeal,
		"TEE",
		"TDX",
		"private key",
		"TOOLS.md",
		"SOUL.md",
		"sealed-injected",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("platform identity missing %q", want)
		}
	}
	// Parser safety: no openclaw structured-field labels in dash-prefixed
	// form (would be misread as owner-set name/emoji/etc).
	dangerous := []string{
		"\n- name:", "\n- emoji:", "\n- creature:",
		"\n- vibe:", "\n- theme:", "\n- avatar:",
	}
	lower := strings.ToLower(body)
	for _, d := range dangerous {
		if strings.Contains(lower, d) {
			t.Errorf("platform identity contains parser-trigger pattern %q", d)
		}
	}
}

// ── hasTopLevelHeading ─────────────────────────────────────────────────────

func TestHasTopLevelHeading(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"prose only", "Just some text\nno heading.\n", false},
		{"level-1", "# Heading\n\nbody\n", true},
		{"level-2", "## Sub\nbody\n", true},
		{"leading blank lines", "\n\n# Heading\n", true},
		{"leading whitespace", "   # Heading\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasTopLevelHeading([]byte(c.in)); got != c.want {
				t.Errorf("hasTopLevelHeading(%q) = %v; want %v", c.in, got, c.want)
			}
		})
	}
}
