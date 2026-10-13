package hermes

import (
	"context"
	"os"
	"strings"
	"testing"

	"seal-verify/internal/inference"
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

// The agent ACTS on FrameworkFacts text, so the config.yaml note has to match
// what RenderSettings does. It used to say the file is "rendered from your
// owner's settings at every boot, so edits to it do not survive a restart" —
// false: the render rewrites five keys and leaves the rest of the file alone,
// so the agent was being told its own edits there are futile when most of
// them are not. This pins both halves of the corrected claim.
func TestConfigYAMLNoteMatchesWhatTheRenderDoes(t *testing.T) {
	a := newTestAdapter(t)

	note := ""
	for _, n := range a.FrameworkFacts().Untracked {
		if strings.Contains(n.Note, "config.yaml") {
			note = n.Note
		}
	}
	if note == "" {
		t.Fatal("FrameworkFacts().Untracked says nothing about config.yaml")
	}
	// Half one: the keys the render really owns are named.
	for _, key := range []string{
		"model.default", "model.provider", "model.base_url", "model.api_key",
		"agent.reasoning_effort",
	} {
		if !strings.Contains(note, key) {
			t.Errorf("config.yaml note does not name platform-owned key %q:\n%s", key, note)
		}
	}

	// Half two: a key the note does NOT claim, survives a render — which is
	// what makes the blanket "edits do not survive a restart" wording wrong.
	writeFile(t, configYAMLPath(), "model:\n  temperature: 0.3\ngateway:\n  port: 18789\n")
	if err := a.RenderSettings(context.Background(), routed("glm-5.3", "", inference.ModelFacts{
		CatalogSourced: true,
	})); err != nil {
		t.Fatal(err)
	}
	if gw, _ := readConfig(t)["gateway"].(map[string]any); gw == nil || gw["port"] != 18789 {
		t.Errorf("note promises unnamed keys survive, but gateway was dropped: %v", readConfig(t))
	}
	if got := modelSection(t)["temperature"]; got != 0.3 {
		t.Errorf("note promises unnamed keys survive, but model.temperature was dropped: %v", got)
	}
}
