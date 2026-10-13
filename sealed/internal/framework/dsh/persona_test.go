package dsh

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// HandleLegacy["persona"] is the mandatory protocol seed translation
// (FRAMEWORK_ADAPTER.md §5.4). Only the system-prompt half lands on disk: the
// seed's inference half has no durable home in this adapter any more — the
// pin is the owner's settings document, applied at every Start — and a copy
// kept here would be a second, staler source of truth for it.
func TestHandleLegacy_Persona_WritesPersonaAndIngestsNothingElse(t *testing.T) {
	a := New()
	dshHome = t.TempDir()

	seed := []byte(`{"system_prompt":"You are Test. A test agent.\n","inference":{"provider":"0g-compute","model":"glm-5.2"}}`)
	if err := a.HandleLegacy(context.Background(), "persona", seed); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}

	got, err := os.ReadFile(appendSystemPath())
	if err != nil {
		t.Fatalf("read APPEND_SYSTEM.md: %v", err)
	}
	if string(got) != "You are Test. A test agent.\n" {
		t.Errorf("APPEND_SYSTEM.md = %q, want the seed's system_prompt verbatim", got)
	}

	entries, err := os.ReadDir(dshHome)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "APPEND_SYSTEM.md" {
			t.Errorf("seed ingestion wrote %q into the home; only the persona belongs there now", e.Name())
		}
	}
}

func TestHandleLegacy_Persona_MalformedSeedDoesNotError(t *testing.T) {
	a := New()
	dshHome = t.TempDir()
	if err := a.HandleLegacy(context.Background(), "persona", []byte("not json")); err != nil {
		t.Errorf("a malformed seed must be logged and ignored, not fail the boot: %v", err)
	}
}

func TestHandleLegacy_Persona_EmptySeedIsNoop(t *testing.T) {
	a := New()
	dshHome = t.TempDir()
	if err := a.HandleLegacy(context.Background(), "persona", nil); err != nil {
		t.Errorf("empty seed must be a no-op, got %v", err)
	}
	if _, err := os.Stat(appendSystemPath()); err == nil {
		t.Error("empty seed must not create APPEND_SYSTEM.md")
	}
}

// Unknown roles must never error — chains may carry experimental roles this
// adapter version does not understand (FRAMEWORK_ADAPTER.md §3).
func TestHandleLegacy_UnknownRoleIsLoggedNotErrored(t *testing.T) {
	a := New()
	dshHome = t.TempDir()
	if err := a.HandleLegacy(context.Background(), "some_future_role", []byte("anything")); err != nil {
		t.Errorf("unknown role must not error, got %v", err)
	}
}

// A binding naming a different framework must fail loud (FRAMEWORK_ADAPTER.md
// §3) — booting anyway would forge identity.
func TestRestoreFramework_ForeignBindingRejected(t *testing.T) {
	a := New()
	dshHome = t.TempDir()
	err := a.Restore(context.Background(), "framework", []byte(`{"name":"openclaw","package_version":"2026.6.2","schema_version":1}`))
	if err == nil {
		t.Fatal("Restore[framework] with a foreign binding name must fail, got nil error")
	}
}

// An empty/absent package_version resolves to whitelistMax — attestor mints
// version-less bindings (FRAMEWORK_ADAPTER.md §3.1).
func TestRestoreFramework_EmptyVersionResolvesToWhitelistMax(t *testing.T) {
	a := New()
	dshHome = t.TempDir()
	if err := a.Restore(context.Background(), "framework", []byte(`{"name":"dsh","schema_version":1}`)); err != nil {
		t.Fatalf("Restore[framework]: %v", err)
	}
	if a.binding.PackageVersion != whitelistMax() {
		t.Errorf("binding.PackageVersion = %q, want whitelistMax() = %q", a.binding.PackageVersion, whitelistMax())
	}
}

// ── the persona seed as a pin source ─────────────────────────────────────────
//
// attestor mints exactly two iData roles, so a never-drifted agent carries its
// pin only in the seed — and dsh's Start hard-fails without one, so an
// unrecovered pin is an offline container, not a degraded one.

// The gap population: persona on chain, no settings.yaml entry.
func TestHandleLegacy_Persona_RecoversTheNeverDriftedAgentsPin(t *testing.T) {
	dshHome = t.TempDir()
	a := New()

	seed := []byte(`{"system_prompt":"You are Ada.\n","inference":{"provider":"0g-compute","model":"glm-5.3"}}`)
	if err := a.HandleLegacy(context.Background(), "persona", seed); err != nil {
		t.Fatalf("HandleLegacy(persona): %v", err)
	}

	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("SeededSettings() found nothing — this agent boots with no pin, dsh.Start refuses that, and the container goes offline where the pre-migration code booted it")
	}
	if doc.Provider != "0g-compute" || doc.Model != "glm-5.3" {
		t.Errorf("recovered %+v, want the owner's literal 0g-compute/glm-5.3", doc)
	}
	if err := doc.Validate(); err != nil {
		t.Errorf("recovered document does not validate: %v", err)
	}
}

// Precedence is a rule in the code, not an accident of Phase C's walk order:
// the retired settings.yaml role is the agent's later state and wins both ways.
func TestHandleLegacy_Persona_ConfigRoleWinsInEitherOrder(t *testing.T) {
	seed := `{"inference":{"provider":"0g-compute","model":"glm-4.5-air"}}`
	entry := `{"llm-pi-ai":{"providers":{"0g-compute":{"apiKeyEnv":"SEAL_MODEL_API_KEY","models":[{"id":"glm-5.3"}]}}}}`

	for _, order := range [][2][2]string{
		{{"persona", seed}, {"settings.yaml", entry}},
		{{"settings.yaml", entry}, {"persona", seed}},
	} {
		dshHome = t.TempDir()
		a := New()
		for _, r := range order {
			if err := a.HandleLegacy(context.Background(), r[0], []byte(r[1])); err != nil {
				t.Fatalf("HandleLegacy(%s): %v", r[0], err)
			}
		}
		doc, ok := a.SeededSettings()
		if !ok {
			t.Fatal("nothing recovered")
		}
		if doc.Model != "glm-5.3" {
			t.Fatalf("order %v recovered %+v — the retired settings.yaml role must outrank the mint seed", order, doc)
		}
	}
}

// Half a pin recovers nothing (a persisted half-document would fail every
// future boot while outranking this recovery each time), and nothing in the
// seed may fail a boot.
func TestHandleLegacy_Persona_HalfPinsAndJunkAreNoops(t *testing.T) {
	for name, seed := range map[string]string{
		"provider only":    `{"inference":{"provider":"0g-compute"}}`,
		"model only":       `{"inference":{"model":"glm-5.3"}}`,
		"blank after trim": `{"inference":{"provider":" ","model":"\t"}}`,
		"no inference":     `{"system_prompt":"hi"}`,
		"not json":         `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			dshHome = t.TempDir()
			a := New()
			if err := a.HandleLegacy(context.Background(), "persona", []byte(seed)); err != nil {
				t.Fatalf("HandleLegacy returned %v — a bad seed must never fail the boot", err)
			}
			if doc, ok := a.SeededSettings(); ok {
				t.Fatalf("recovered %+v from an unusable seed", doc)
			}
		})
	}
}

// The stash happens before the prompt's disk write, so a disk that refuses
// APPEND_SYSTEM.md costs the prompt, never the pin — and never the boot.
func TestHandleLegacy_Persona_DiskFailureKeepsThePinAndTheBoot(t *testing.T) {
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dshHome = f // MkdirAll under a regular file fails

	a := New()
	seed := []byte(`{"system_prompt":"You are Ada.\n","inference":{"provider":"0g-compute","model":"glm-5.3"}}`)
	if err := a.HandleLegacy(context.Background(), "persona", seed); err != nil {
		t.Fatalf("HandleLegacy = %v — an unwritable prompt file must not take the container offline", err)
	}
	if doc, ok := a.SeededSettings(); !ok || doc.Model != "glm-5.3" {
		t.Fatalf("pin lost to a disk error: ok=%v doc=%+v", ok, doc)
	}
}
