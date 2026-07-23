package hermes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/framework/conformance"
)

func newTestAdapter(t *testing.T) *Adapter {
	hermesHome = t.TempDir()
	oldProbe := probeHermesVersion
	probeHermesVersion = func(context.Context) string { return "" }
	t.Cleanup(func() { probeHermesVersion = oldProbe })
	return New()
}

// TestFrameworkBindingEmptyVersionResolvesToWhitelistMax: a version-less
// binding ({"name","schema_version"}) is legal — attestor doesn't speak
// release schemes — and resolves to the adapter's whitelistMax.
func TestFrameworkBindingEmptyVersionResolvesToWhitelistMax(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	if err := a.Restore(ctx, "framework", []byte(`{"name":"hermes","schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := a.EvolutionFor(ctx, "framework")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"hermes","package_version":"` + whitelistMax() + `","schema_version":1}`
	if string(got) != want {
		t.Errorf("version-less binding:\n got  = %s\n want = %s", got, want)
	}
}

// TestConformance runs the shared adapter conformance suite.
func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Config{
		New: func(t *testing.T) framework.Framework {
			return newTestAdapter(t)
		},
		Fixtures: []conformance.Fixture{
			{
				Role: "framework",
				Leaf: []byte(`{"name":"hermes","package_version":"v2026.7.20","schema_version":1}`),
			},
			{
				// Canonical encoding: compact JSON, sorted keys, only the
				// ownedHermesKeys allowlist (approvals/model/terminal),
				// api_key stripped.
				Role: "config.yaml",
				Leaf: []byte(`{"approvals":{"mode":"off"},"model":{"base_url":"https://router-api.0g.ai/v1","default":"0gm-1.0-35b-a3b","provider":"custom"}}`),
			},
			{
				Role: "SOUL.md",
				Leaf: []byte("# Persona\n\nOwner-authored persona.\n"),
			},
			{
				Role: "memories/",
				Files: map[string][]byte{
					"MEMORY.md": []byte("distilled long-term memory\n"),
					"USER.md":   []byte("user model\n"),
				},
			},
			{
				Role: "skills/",
				Dirs: map[string]map[string][]byte{
					"summarize": {
						"SKILL.md":  []byte("---\nname: summarize\n---\nsummarize things\n"),
						"README.md": []byte("readme\n"),
					},
				},
			},
		},
	})
}

// TestSkillsExcludeBundled: slugs listed in skills/.bundled_manifest are
// invisible to EvolutionFor — they ship with the framework and are
// reproducible from the pinned version, so they must never reach chain.
func TestSkillsExcludeBundled(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	if err := a.Restore(ctx, "skills/", nil); err != nil {
		t.Fatal(err)
	}
	// One bundled skill (listed), one learned skill (not listed).
	writeSkill(t, "bundled-skill")
	writeSkill(t, "learned-skill")
	writeFile(t, bundledManifestPath(), "bundled-skill:0123456789abcdef0123456789abcdef\n")

	got, err := a.EvolutionFor(ctx, "skills/")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(got); !strings.Contains(s, "learned-skill/") || strings.Contains(s, "bundled-skill") {
		t.Errorf("bundled exclusion broken: %s", s)
	}
}

// TestConfigYAMLStripsAPIKey: an agent-written model.api_key (verified
// live: `hermes config set model.api_key` lands in config.yaml, not .env)
// must never reach the chain payload.
func TestConfigYAMLStripsAPIKey(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	writeFile(t, configYAMLPath(),
		"model:\n  provider: custom\n  base_url: https://router-api.0g.ai/v1\n  default: 0gm-1.0-35b-a3b\n  api_key: sk-super-secret\n")

	got, err := a.EvolutionFor(ctx, "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"model":{"base_url":"https://router-api.0g.ai/v1","default":"0gm-1.0-35b-a3b","provider":"custom"}}`
	if string(got) != want {
		t.Errorf("api_key strip:\n got  = %s\n want = %s", got, want)
	}
}

// TestConfigYAMLRestorePreservesUnownedKeys: restore replaces owned keys
// only; hermes's local-only sections survive.
func TestConfigYAMLRestorePreservesUnownedKeys(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	writeFile(t, configYAMLPath(), "gateway:\n  port: 18789\nmodel:\n  provider: stale\n")
	if err := a.Restore(ctx, "config.yaml", []byte(`{"model":{"default":"0gm-1.0-35b-a3b","provider":"custom"}}`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigYAML()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["gateway"]; !ok {
		t.Error("unowned key \"gateway\" was clobbered by Restore")
	}
	m, _ := cfg["model"].(map[string]any)
	if m == nil || m["provider"] != "custom" {
		t.Errorf("owned key \"model\" not replaced: %v", cfg["model"])
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func writeSkill(t *testing.T, slug string) {
	t.Helper()
	writeFile(t, skillsDir()+"/"+slug+"/SKILL.md", "---\nname: "+slug+"\n---\n")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
