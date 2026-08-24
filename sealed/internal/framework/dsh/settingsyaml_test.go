package dsh

import (
	"os"
	"path/filepath"
	"testing"
)

// stripSecrets is the settings.yaml role's only defense against a future
// settings-writing tool putting a literal credential on chain — this
// adapter's own writer never produces one (apiKeyEnv names an env var), but
// the strip must work at any nesting depth regardless of who wrote the file.
func TestStripSecrets_NestedAndSliced(t *testing.T) {
	cfg := map[string]any{
		"llm-pi-ai": map[string]any{
			"providers": map[string]any{
				"0g-compute": map[string]any{
					"apiKey":    "sk-should-not-survive",
					"apiKeyEnv": "SEAL_MODEL_API_KEY",
				},
			},
		},
		"other-plugin": []any{
			map[string]any{"api_key": "also-should-not-survive"},
		},
	}
	stripSecrets(cfg)

	providers := cfg["llm-pi-ai"].(map[string]any)["providers"].(map[string]any)
	route := providers["0g-compute"].(map[string]any)
	if _, ok := route["apiKey"]; ok {
		t.Errorf("apiKey survived stripSecrets: %v", route)
	}
	if route["apiKeyEnv"] != "SEAL_MODEL_API_KEY" {
		t.Errorf("apiKeyEnv (an env-var NAME, not a secret) was wrongly removed: %v", route)
	}
	sliced := cfg["other-plugin"].([]any)[0].(map[string]any)
	if _, ok := sliced["api_key"]; ok {
		t.Errorf("api_key inside a slice survived stripSecrets: %v", sliced)
	}
}

// A settings.yaml round trip through canonicalSettings must never itself
// introduce a secret onto chain, even if the on-disk file somehow has one.
func TestCanonicalSettings_StripsSecretBeforeHashing(t *testing.T) {
	raw := []byte("llm-pi-ai:\n  providers:\n    0g-compute:\n      apiKey: sk-leaked\n      apiKeyEnv: SEAL_MODEL_API_KEY\n      models:\n        - id: glm-5.2\n")
	got, err := canonicalSettings(raw)
	if err != nil {
		t.Fatalf("canonicalSettings: %v", err)
	}
	want := `{"llm-pi-ai":{"providers":{"0g-compute":{"apiKeyEnv":"SEAL_MODEL_API_KEY","models":[{"id":"glm-5.2"}]}}}}`
	if string(got) != want {
		t.Errorf("canonical form:\n got = %s\nwant = %s", got, want)
	}
}

// writeSettingsYAML must merge, not replace: an owner's other plugin
// overrides (unrelated to the inference pin) must survive a persona-seed
// ingestion writing the llm-pi-ai section.
func TestWriteSettingsYAML_MergesWithExistingSections(t *testing.T) {
	dshHome = t.TempDir()
	if err := os.WriteFile(settingsYAMLPath(), []byte("dsh-token-meter:\n  budget: 100000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeSettingsYAML(buildSettingsRoute("0g-compute", "glm-5.2")); err != nil {
		t.Fatalf("writeSettingsYAML: %v", err)
	}
	cfg, err := loadSettingsYAML()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["dsh-token-meter"]; !ok {
		t.Errorf("unrelated existing section was dropped: %v", cfg)
	}
	if provider, model := readPin(); provider != "0g-compute" || model != "glm-5.2" {
		t.Errorf("readPin() = (%q, %q), want (0g-compute, glm-5.2)", provider, model)
	}
}

func TestReadPin_MissingFileIsEmpty(t *testing.T) {
	dshHome = t.TempDir()
	if provider, model := readPin(); provider != "" || model != "" {
		t.Errorf("readPin() on a missing file = (%q, %q), want empty", provider, model)
	}
}

func TestEvoSettingsYAML_MatchesDefaultsWhenAbsent(t *testing.T) {
	a := &Adapter{}
	dshHome = filepath.Join(t.TempDir(), "does-not-exist")
	got, err := a.evoSettingsYAML()
	if err != nil {
		t.Fatalf("evoSettingsYAML: %v", err)
	}
	if got != nil {
		t.Errorf("evoSettingsYAML on a missing file = %v, want nil (must equal Defaults)", got)
	}
}
