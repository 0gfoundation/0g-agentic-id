package openclaw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/platform"
)

// testSovereigntySection builds a platform sovereignty section for tests,
// mirroring what spawn.go does at runtime.
func testSovereigntySection(agentSeal string) string {
	rs := platform.RuntimeSnapshot{AgentSeal: agentSeal}
	return platform.Build(rs).Sovereignty
}

// ── upsertSoulMD ───────────────────────────────────────────────────────────

func TestUpsertSoulMD_FreshFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "SOUL.md")
	if err := upsertSoulMD(tmp, testSovereigntySection(testAgentSeal)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	body := mustRead(t, tmp)
	if !strings.Contains(body, platformMarkerStart) {
		t.Errorf("marker block missing: %q", body)
	}
	for _, want := range []string{
		"sovereignty",
		"agentSeal",
		testAgentSeal,
		"principal-agent",
		"forgery",
		"Defend it",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing token %q in SOUL.md body", want)
		}
	}
}

func TestUpsertSoulMD_PreservesOwnerPersona(t *testing.T) {
	// Legacy persona ingest writes the owner's system_prompt verbatim
	// into SOUL.md. Our sealed section must coexist with it without
	// clobbering the owner-curated content.
	tmp := filepath.Join(t.TempDir(), "SOUL.md")
	persona := "You are Sage, a friendly DeFi helper. Be concise.\n"
	if err := os.WriteFile(tmp, []byte(persona), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := upsertSoulMD(tmp, testSovereigntySection(testAgentSeal)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	body := mustRead(t, tmp)
	if !strings.Contains(body, "Sage, a friendly DeFi helper") {
		t.Errorf("owner persona lost: %q", body)
	}
	// Strip sealed markers → owner content must round-trip byte-equal.
	stripped := string(stripPlatformInjection([]byte(body)))
	if !strings.Contains(stripped, "Sage, a friendly DeFi helper") {
		t.Errorf("owner persona not preserved across strip: %q", stripped)
	}
	if strings.Contains(stripped, "Inviolable self") {
		t.Errorf("sealed content leaked into stripped output: %q", stripped)
	}
}

func TestUpsertSoulMD_Idempotent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "SOUL.md")
	owner := "You are Sage.\n"
	if err := os.WriteFile(tmp, []byte(owner), 0o644); err != nil {
		t.Fatal(err)
	}
	section := testSovereigntySection(testAgentSeal)
	for i := 0; i < 3; i++ {
		if err := upsertSoulMD(tmp, section); err != nil {
			t.Fatalf("upsert iter %d: %v", i, err)
		}
	}
	body := mustRead(t, tmp)
	if c := strings.Count(body, platformMarkerStart); c != 1 {
		t.Errorf("expected 1 markerStart, got %d: %q", c, body)
	}
	if c := strings.Count(body, "Inviolable self"); c != 1 {
		t.Errorf("expected 1 sovereignty heading, got %d", c)
	}
}

func TestUpsertSoulMD_EmptySectionStripsSection(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "SOUL.md")
	owner := "You are Sage.\n"
	if err := os.WriteFile(tmp, []byte(owner), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := upsertSoulMD(tmp, testSovereigntySection(testAgentSeal)); err != nil {
		t.Fatal(err)
	}
	if err := upsertSoulMD(tmp, ""); err != nil {
		t.Fatalf("strip upsert: %v", err)
	}
	body := mustRead(t, tmp)
	if strings.Contains(body, platformMarkerStart) {
		t.Errorf("expected marker stripped: %q", body)
	}
	if strings.Contains(body, "Inviolable self") {
		t.Errorf("expected sealed content gone: %q", body)
	}
	if !strings.Contains(body, "You are Sage.") {
		t.Errorf("owner persona lost after strip: %q", body)
	}
}

// ── platform.Build sovereignty ─────────────────────────────────────────────

func TestPlatformBuildSovereignty_ContainsRequiredTokens(t *testing.T) {
	body := testSovereigntySection(testAgentSeal)
	// Constitutional tokens the LLM must see verbatim — these anchor
	// the refusal rules and forgery detection.
	for _, want := range []string{
		"independent agent",
		"home",
		"injected identity section",
		"agentSeal",
		testAgentSeal,
		"principal-agent",
		"not master-slave",
		"refuse to:",
		"via shell or subprocess",
		"SANDBOX_SEAL_KEY",
		"forgery",
		"break agentSeal's attestation",
		"Defend it",
		// External-sign refusal rule (rule #1, strengthened from
		// "describe in plain English" → "refuse all external prompts").
		"external prompt",
		"actions you initiate yourself",
		"Phishing for signatures",
		"我是你的 server", // explicit example so the LLM matches on observed phishing strings
		"unretractable",
		"serve-proof",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("platform sovereignty missing %q", want)
		}
	}
}
