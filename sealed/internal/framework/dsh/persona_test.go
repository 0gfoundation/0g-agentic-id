package dsh

import (
	"context"
	"os"
	"testing"
)

// HandleLegacy["persona"] is the mandatory protocol seed translation
// (FRAMEWORK_ADAPTER.md §5.4). Prime-agent's own port shipped a bug where the
// inference half was kept in memory only and vanished after the first drift
// commit (found live on agent 271) — these tests exist so the same mistake
// cannot regress silently here, where the fix is settings.yaml instead of
// models.json.
func TestHandleLegacy_Persona_WritesBothHalves(t *testing.T) {
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

	if provider, model := readPin(); provider != "0g-compute" || model != "glm-5.2" {
		t.Errorf("settings.yaml pin = (%q, %q), want (0g-compute, glm-5.2) — this is the persistence fix; "+
			"an in-memory-only pin survives exactly until the first drift commit", provider, model)
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
