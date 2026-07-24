package openclaw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"seal-verify/internal/platform"
)

func TestStripPlatformInjection_NoMarker(t *testing.T) {
	in := []byte("# TOOLS\n\nOwner content here.\n")
	out := stripPlatformInjection(in)
	if string(out) != string(in) {
		t.Errorf("expected unchanged, got: %q", string(out))
	}
}

func TestStripPlatformInjection_FullSection(t *testing.T) {
	// The "\n\n" before the marker is one owner newline + the section's
	// own separator; strip removes exactly the separator and preserves
	// the owner's trailing newline byte-exactly. (The historical trim-all
	// behaviour ate the owner's "\n" and phantom-drifted every injected
	// file once per agent lifetime.)
	in := []byte("# TOOLS\n\nOwner content.\n\n" +
		platformMarkerStart + "\n" +
		"## Environment\n" +
		"injected stuff\n" +
		platformMarkerEnd + "\n")
	out := stripPlatformInjection(in)
	want := "# TOOLS\n\nOwner content.\n"
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
		"agent text after an unpaired marker\n")
	out := stripPlatformInjection(in)
	// A start with no end is owner content, not a section: the agent can
	// quote the marker (it reads it in its context files every turn), and
	// the old truncate-to-EOF behaviour silently destroyed everything
	// below the quote. A genuinely truncated sealed write can't be
	// observed here — Restore rewrites the file from chain plaintext
	// before the first upsert of a boot.
	if string(out) != string(in) {
		t.Errorf("unpaired start must strip nothing\n want: %q\n  got: %q", string(in), string(out))
	}
}

// makeTestPlatformContext builds a minimal PlatformContext suitable for
// upsertToolsMD tests. Only Capabilities is populated (signing + URL);
// Constraints and Runtime are empty so the test can verify the basics.
func makeTestPlatformContext(publicURL string) platform.PlatformContext {
	rs := platform.RuntimeSnapshot{
		PublicURL:    publicURL,
		AgentSeal:    "0xTestAgentSeal0000000000000000000000000001",
		SealSignSock: "/run/seal-sign.sock",
	}
	return platform.Build(rs)
}

func TestUpsertPlatformSection_FreshFile(t *testing.T) {
	tmp := t.TempDir() + "/TOOLS.md"
	pc := makeTestPlatformContext("http://8080-x.example.com:4000")
	if err := upsertToolsMD(tmp, pc, platform.RenderFrameworkFacts(New().FrameworkFacts())); err != nil {
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
	pc := makeTestPlatformContext("http://x.example.com")
	if err := upsertToolsMD(tmp, pc, platform.RenderFrameworkFacts(New().FrameworkFacts())); err != nil {
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
	pc := makeTestPlatformContext("http://8080-test.example.com")
	for i := 0; i < 3; i++ {
		if err := upsertToolsMD(tmp, pc, platform.RenderFrameworkFacts(New().FrameworkFacts())); err != nil {
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

func TestUpsertPlatformSection_EmptyContextStripsSection(t *testing.T) {
	tmp := t.TempDir() + "/TOOLS.md"
	pc := makeTestPlatformContext("http://x.example.com")
	if err := upsertToolsMD(tmp, pc, platform.RenderFrameworkFacts(New().FrameworkFacts())); err != nil {
		t.Fatal(err)
	}
	// Empty PlatformContext → all sections empty → strip.
	emptyPC := platform.PlatformContext{}
	if err := upsertToolsMD(tmp, emptyPC, ""); err != nil {
		t.Fatalf("upsert with empty context: %v", err)
	}
	body := mustRead(t, tmp)
	if strings.Contains(body, platformMarkerStart) || strings.Contains(body, "AGENT_PUBLIC_URL") {
		t.Errorf("expected platform section stripped, got: %q", body)
	}
}

// TestUpsertPlatformSection_IncludesConstraints verifies that TOOLS.md
// carries BOTH the platform constraints (drift mechanics) and the
// adapter-authored framework facts (version whitelist from
// supportedOpenclawVersions, config allowlist, persistent-state layout)
// — the authorship split of the platform/adapter refactor.
func TestUpsertPlatformSection_IncludesConstraints(t *testing.T) {
	useTestWhitelist(t, []string{"2026.5.6", "2026.6.8"})
	tmp := t.TempDir() + "/TOOLS.md"
	rs := platform.RuntimeSnapshot{
		PublicURL:    "http://x.example.com",
		AgentSeal:    "0xTest",
		SealSignSock: "/run/seal-sign.sock",
		WhitelistMax: "2026.6.8",
	}
	pc := platform.Build(rs)
	if err := upsertToolsMD(tmp, pc, platform.RenderFrameworkFacts(New().FrameworkFacts())); err != nil {
		t.Fatalf("upsert err: %v", err)
	}
	body := mustRead(t, tmp)
	if !strings.Contains(body, "Runtime constraints") {
		t.Errorf("missing constraints section: %q", body)
	}
	if !strings.Contains(body, "Framework version whitelist") {
		t.Errorf("missing whitelist mention: %q", body)
	}
	if !strings.Contains(body, "2026.6.8") {
		t.Errorf("missing whitelist max version: %q", body)
	}
	// Adapter-authored facts must not have been lost in the move.
	if !strings.Contains(body, "npm install openclaw@<max>") {
		t.Errorf("missing openclaw reconcile fact: %q", body)
	}
	if !strings.Contains(body, "`~/.openclaw/openclaw.json`") {
		t.Errorf("missing persistent-state tracked paths: %q", body)
	}
	if !strings.Contains(body, "Config allowlist") {
		t.Errorf("missing config allowlist fact: %q", body)
	}
}

// TestUpsertPlatformSection_IncludesRuntimeSnapshot verifies the per-boot
// runtime snapshot table is injected.
func TestUpsertPlatformSection_IncludesRuntimeSnapshot(t *testing.T) {
	tmp := t.TempDir() + "/TOOLS.md"
	rs := platform.RuntimeSnapshot{
		PublicURL:        "http://x.example.com",
		AgentSeal:        "0xTestAgent",
		SealSignSock:     "/run/seal-sign.sock",
		Provider:         "openai",
		Model:            "glm-5.2",
		ZGComputeRouted:  false,
		FrameworkVersion: "2026.5.6",
	}
	pc := platform.Build(rs)
	if err := upsertToolsMD(tmp, pc, platform.RenderFrameworkFacts(New().FrameworkFacts())); err != nil {
		t.Fatalf("upsert err: %v", err)
	}
	body := mustRead(t, tmp)
	if !strings.Contains(body, "Runtime snapshot") {
		t.Errorf("missing runtime snapshot section: %q", body)
	}
	if !strings.Contains(body, "openai/glm-5.2") {
		t.Errorf("missing provider/model in snapshot: %q", body)
	}
	if !strings.Contains(body, "2026.5.6") {
		t.Errorf("missing framework version in snapshot: %q", body)
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

// ── helpers ─────────────────────────────────────────────────────────────────

// useTempHome redirects openclawHome to t.TempDir() so disk-touching tests
// don't pollute /root/.openclaw. Restores the original value after the test.
func useTempHome(t *testing.T) {
	t.Helper()
	prev := openclawHome
	openclawHome = t.TempDir()
	t.Cleanup(func() { openclawHome = prev })
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

// restoredVersion runs a framework Restore with the given pinned version
// and returns the package_version that landed in cfg — i.e. what Start
// would npm-install.
func restoredVersion(t *testing.T, pin string) string {
	t.Helper()
	a := &Adapter{}
	binding := []byte(`{"name":"openclaw","package_version":"` + pin + `","schema_version":1}`)
	if err := a.Restore(context.Background(), "framework", binding); err != nil {
		t.Fatalf("Restore(%q): %v", pin, err)
	}
	return a.cfg.framework.PackageVersion
}

// A pin outside the whitelist is coerced to the nearest validated
// version at install — sealed never npm-installs a release it hasn't
// been validated against (previously the pin was installed as-is and
// only pulled back on a later drift).
func TestAdapter_RestoreFramework_CoercesUnvalidatedPin(t *testing.T) {
	useTestWhitelist(t, []string{"2026.5.6", "2026.5.7"})
	if got := restoredVersion(t, "2026.9.9"); got != "2026.5.7" {
		t.Errorf("pin above max: got %q, want whitelistMax 2026.5.7", got)
	}
	if got := restoredVersion(t, "2025.1.1"); got != "2026.5.6" {
		t.Errorf("pin below all: got %q, want oldest validated 2026.5.6", got)
	}
}

// Whitelisted pins are honored — including ones below whitelistMax.
func TestAdapter_RestoreFramework_HonorsWhitelistedPin(t *testing.T) {
	useTestWhitelist(t, []string{"2026.5.6", "2026.5.7"})
	if got := restoredVersion(t, "2026.5.6"); got != "2026.5.6" {
		t.Errorf("whitelisted below-max pin: got %q, want 2026.5.6", got)
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
