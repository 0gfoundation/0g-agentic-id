package hermes

import (
	"os"
	"strings"
	"testing"

	"seal-verify/internal/platform"
)

// The platform section must be ON DISK (SOUL.md, so the agent reads how to
// expose a service) but STRIPPED from the chain payload (evoSoulMD), or the
// per-boot platform text phantom-drifts onto chain every restart. This is
// the injection↔strip pairing that the v1 gap-fix depends on.
func TestPlatformInjectionOnDiskNotOnChain(t *testing.T) {
	hermesHome = t.TempDir()
	persona := "# Persona\n\nI am a fortune teller.\n"
	if err := os.WriteFile(soulMDPath(), []byte(persona), 0o644); err != nil {
		t.Fatal(err)
	}

	pc := platform.PlatformContext{
		Capabilities: "## Environment\n\nRegister a service at `$SEAL_SIGN_SOCK/services` so the proxy exposes it.\n",
	}
	if err := upsertSoulMD(pc, New().FrameworkFacts()); err != nil {
		t.Fatal(err)
	}

	// On disk: agent must see both the persona and the exposure instructions.
	disk, err := os.ReadFile(soulMDPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(disk), "$SEAL_SIGN_SOCK/services") {
		t.Error("platform exposure text missing from SOUL.md on disk — agent wouldn't learn it")
	}
	if !strings.Contains(string(disk), "fortune teller") {
		t.Error("owner persona clobbered by injection")
	}

	// On chain (evoSoulMD): persona only, no platform text.
	got, err := New().evoSoulMD()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "SEAL_SIGN_SOCK") {
		t.Error("platform text leaked into the chain payload (evoSoulMD didn't strip) — will phantom-drift")
	}
	if !strings.Contains(string(got), "fortune teller") {
		t.Error("persona missing from chain payload")
	}
}

// A version-less-marker SOUL.md (no injection) round-trips unchanged —
// StripInjected is a no-op, so a never-Started agent's persona is intact.
func TestEvoSoulMDNoMarkerNoOp(t *testing.T) {
	hermesHome = t.TempDir()
	persona := "# Persona\n\nplain persona, no markers\n"
	if err := os.WriteFile(soulMDPath(), []byte(persona), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := New().evoSoulMD()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != persona {
		t.Errorf("no-marker SOUL.md changed by evoSoulMD:\n got  = %q\n want = %q", got, persona)
	}
}
