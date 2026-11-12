package harness

import (
	"context"
	"encoding/json"
	"path/filepath"
	"seal-verify/internal/privsep"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/framework/conformance"
)

func TestZGHRestoresMintAndEvolvedPersona(t *testing.T) {
	for _, evolved := range []bool{false, true} {
		t.Run(map[bool]string{false: "mint", true: "evolved"}[evolved], func(t *testing.T) {
			old := dshHome
			dshHome = t.TempDir()
			t.Cleanup(func() { dshHome = old })
			a := NewZGH()
			ctx := context.Background()
			if err := a.Restore(ctx, "framework", []byte(`{"name":"0g-harness","package_version":"0.2.0","schema_version":1}`)); err != nil {
				t.Fatal(err)
			}
			var binding map[string]any
			raw, _ := a.EvolutionFor(ctx, "framework")
			_ = json.Unmarshal(raw, &binding)
			if binding["name"] != "0g-harness" || binding["package_version"] != "0.3.0" {
				t.Fatalf("binding %s", raw)
			}
			if evolved {
				if err := a.Restore(ctx, "APPEND_SYSTEM.md", []byte("evolved persona\n")); err != nil {
					t.Fatal(err)
				}
			}
			seed := []byte(`{"system_prompt":"mint persona","inference":{"provider":"0g-compute","model":"test"}}`)
			for i := 0; i < 2; i++ {
				if err := a.HandleLegacy(ctx, "persona", seed); err != nil {
					t.Fatal(err)
				}
			}
			got, err := a.EvolutionFor(ctx, "APPEND_SYSTEM.md")
			if err != nil {
				t.Fatal(err)
			}
			want := "mint persona"
			if evolved {
				want = "evolved persona\n"
			}
			if string(got) != want {
				t.Fatalf("persona %q, want %q", got, want)
			}
		})
	}
}

func TestZGHRoleConformance(t *testing.T) {
	conformance.Run(t, conformance.Config{New: func(t *testing.T) framework.Framework { dshHome = t.TempDir(); return NewZGH() }, Fixtures: []conformance.Fixture{
		{Role: "APPEND_SYSTEM.md", Leaf: []byte("portable persona\n")},
		{Role: "skills/", Files: map[string][]byte{"legacy.md": []byte("# Legacy skill\n")}, Dirs: map[string]map[string][]byte{"modern": {"SKILL.md": []byte("# Modern skill\n")}}},
	}})
}

func TestZGHCapabilitiesKeepNativeTasksDistinct(t *testing.T) {
	kinds := map[string]bool{}
	for _, r := range NewZGH().FrameworkRoutes() {
		kinds[r.Kind] = true
	}
	for _, k := range []string{"chat", "zgh-sessions-v1", "zgh-tasks-v1"} {
		if !kinds[k] {
			t.Errorf("missing %s", k)
		}
	}
	for _, k := range []string{"tasks", "responses", "inbox", "schedules"} {
		if kinds[k] {
			t.Errorf("incompatible capability %s", k)
		}
	}
}

func TestZGHRejectsUnreadableLegacyRoles(t *testing.T) {
	old := dshHome
	dshHome = t.TempDir()
	t.Cleanup(func() { dshHome = old })
	for role, raw := range map[string]string{"persona": "{broken", "settings.yaml": "unsupported settings"} {
		if err := NewZGH().HandleLegacy(context.Background(), role, []byte(raw)); err == nil {
			t.Errorf("%s: would retire unreadable data", role)
		}
	}
	a := NewZGH()
	raw := []byte(`{"llm-pi-ai":{"providers":{"0g-compute":{"models":[{"id":"glm-5.3"}]}}}}`)
	if err := a.HandleLegacy(context.Background(), "settings.yaml", raw); err != nil {
		t.Fatal(err)
	}
	doc, ok := a.SeededSettings()
	if !ok || doc.Model != "glm-5.3" {
		t.Fatalf("legacy pin %+v %v", doc, ok)
	}
}

func TestZGHRuntimePackageCompatibility(t *testing.T) {
	dir := t.TempDir()
	if err := NewZGH().ValidateRuntimePackage(dir); err == nil {
		t.Fatal("accepted package without zgh metadata")
	}
	if err := privsep.WriteFile(filepath.Join(dir, "runtime.json"), []byte(`{"backend":"zgh","integration_version":"0.3.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := NewZGH().ValidateRuntimePackage(dir); err != nil {
		t.Fatal(err)
	}
	if err := privsep.WriteFile(filepath.Join(dir, "runtime.json"), []byte(`{"backend":"dsh","integration_version":"0.3.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := NewZGH().ValidateRuntimePackage(dir); err == nil {
		t.Fatal("accepted incompatible runtime")
	}
	if err := New().ValidateRuntimePackage(dir); err != nil {
		t.Fatal("changed DSH package validation")
	}
}
