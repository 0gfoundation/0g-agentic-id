package dsh

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// role="settings.yaml" — the inference route pin, in DSH's settings-file YAML
// shape ($DSH_HOME/settings.yaml).
//
// NOTE the bridge deliberately does NOT mount `@deepseek-ai/dsh-settings-file`
// (see bridge/bridge.mjs): its hot-reload would layer this file OVER the
// composition, letting an agent edit inject an arbitrary baseURL/apiKeyEnv
// route live. So DSH itself never reads this file. It is purely THIS adapter's
// durable store for the pin: Start reads it (readPin) and passes provider +
// model to the bridge as env; the bridge builds the llm-pi-ai route from that.
//
// The role exists for the same reason prime-agent's models.json does
// (FRAMEWORK_ADAPTER.md §13): the mint-time `persona` seed is consumed once
// and gone from chain at the first drift commit, so the inference pin needs a
// durable, path-driven home or every boot after that first commit comes up
// with no model. The file keeps DSH's own settings shape (so the format stays
// recognizable) even though nothing in the composition reads it.
//
// The wire encoding is canonical JSON (compact, sorted keys), NOT YAML — YAML
// serialization is not deterministic enough to hash. The adapter converts at
// the edge: YAML on disk (what DSH reads), JSON on chain (what the
// watcher/uploader hashes). Same split as hermes's config.yaml
// (see yamlio.go's doc comment there).
//
// It carries no literal secret: the apiKeyEnv field names an ENVIRONMENT
// VARIABLE the plugin resolves at request time, never a key value. stripSecrets
// deletes any "apiKey"/"api_key" that ends up there anyway — defense in depth
// against a future settings-writing tool, not something this adapter's own
// writer ever produces (compare hermes's stripSecrets, which guards the same
// class of self-inflicted leak).

// apiKeyEnvRef is the env var the settings.yaml entry points at, rather than a
// literal key. Must match what the bridge exports to the DSH process.
const apiKeyEnvRef = "SEAL_MODEL_API_KEY"

// llmPluginID is the composition entry id whose config settings.yaml overrides.
// `@deepseek-ai/dsh-llm-pi-ai` is the OpenAI/Anthropic-compatible-endpoint
// adapter (arbitrary baseURL, per FRAMEWORK_ADAPTER.md's "encode HOW, not
// WHAT" rule for provider routing) — the same role prime-agent's custom
// models.json provider entry and hermes's ANTHROPIC_BASE_URL routing play.
const llmPluginID = "llm-pi-ai"

// buildSettingsRoute renders the pin as one llm-pi-ai provider route, keyed by
// provider name so the agent's own model listing shows where inference
// actually goes (never masquerading as a built-in).
func buildSettingsRoute(provider, model string) map[string]any {
	return map[string]any{
		llmPluginID: map[string]any{
			"providers": map[string]any{
				provider: map[string]any{
					"apiKeyEnv": apiKeyEnvRef,
					"models":    []any{map[string]any{"id": model}},
				},
			},
		},
	}
}

// canonicalSettings re-marshals settings bytes deterministically: parse as a
// generic string-keyed map (yaml.v3 → map[string]any, directly
// json.Marshal-able), strip any secret that should never reach chain, then
// let encoding/json sort map keys at every level.
func canonicalSettings(raw []byte) ([]byte, error) {
	cfg := map[string]any{}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse settings.yaml: %w", err)
	}
	if cfg == nil {
		return nil, nil
	}
	stripSecrets(cfg)
	if len(cfg) == 0 {
		return nil, nil
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal settings.yaml: %w", err)
	}
	return out, nil
}

// stripSecrets recursively deletes literal-key-shaped fields from
// string-keyed maps (descending into nested maps and slices). See the package
// doc: this adapter's own writer never produces one, but a future
// settings-writing tool must not be able to put a secret on chain silently.
func stripSecrets(v any) {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "apiKey")
		delete(t, "api_key")
		for _, child := range t {
			stripSecrets(child)
		}
	case []any:
		for _, child := range t {
			stripSecrets(child)
		}
	}
}

// writeSettingsYAML lands the pin on disk, merging into any existing content
// so an owner's other settings (unrelated plugin overrides) survive.
func writeSettingsYAML(patch map[string]any) error {
	cfg, err := loadSettingsYAML()
	if err != nil {
		return err
	}
	for k, v := range patch {
		cfg[k] = v
	}
	return saveSettingsYAML(cfg)
}

func loadSettingsYAML() (map[string]any, error) {
	raw, err := os.ReadFile(settingsYAMLPath())
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", settingsYAMLPath(), err)
	}
	cfg := map[string]any{}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", settingsYAMLPath(), err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

func saveSettingsYAML(cfg map[string]any) error {
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal settings.yaml: %w", err)
	}
	if err := ensureDir(dshHome); err != nil {
		return err
	}
	if err := os.WriteFile(settingsYAMLPath(), out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", settingsYAMLPath(), err)
	}
	return nil
}

// readPin returns the provider/model this agent is pinned to, from the
// tracked settings.yaml's llm-pi-ai section. Empty strings when there is no
// pin yet.
func readPin() (provider, model string) {
	cfg, err := loadSettingsYAML()
	if err != nil {
		return "", ""
	}
	section, _ := cfg[llmPluginID].(map[string]any)
	providers, _ := section["providers"].(map[string]any)
	// Deterministic pick: sort provider names so a multi-provider file (which
	// this adapter never writes, but a future edit might) yields a stable pin
	// rather than a random map-iteration order.
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		route, _ := providers[name].(map[string]any)
		models, _ := route["models"].([]any)
		if len(models) > 0 {
			if m, ok := models[0].(map[string]any); ok {
				if id, ok := m["id"].(string); ok {
					return name, id
				}
			}
		}
		return name, ""
	}
	return "", ""
}

// evoSettingsYAML returns the canonical plaintext for the role. A missing or
// section-less file is "no content", matching Defaults.
func (a *Adapter) evoSettingsYAML() ([]byte, error) {
	raw, err := os.ReadFile(settingsYAMLPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dsh evoSettingsYAML: read %s: %w", settingsYAMLPath(), err)
	}
	out, err := canonicalSettings(raw)
	if err != nil {
		return nil, fmt.Errorf("dsh evoSettingsYAML: %w", err)
	}
	return out, nil
}

// restoreSettingsYAML lands the chain plaintext. nil means "chain has no
// entry": leave an existing file alone (a restart must not wipe a pin the
// agent is running on) but create nothing, so the absent-on-chain invariant
// holds.
func (a *Adapter) restoreSettingsYAML(plaintext []byte) error {
	if len(plaintext) == 0 {
		return nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		return fmt.Errorf("dsh.Restore[settings.yaml]: parse: %w", err)
	}
	stripSecrets(cfg)
	return saveSettingsYAML(cfg)
}
