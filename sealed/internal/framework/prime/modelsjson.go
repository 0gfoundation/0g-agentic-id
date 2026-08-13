package prime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// role="models.json" — the inference pin, in the framework's own format.
//
// This role exists because of a bug the live boot found. FRAMEWORK_ADAPTER.md
// §5.4 is explicit that `persona` is a mint-time SEED: the uploader drops every
// chain entry outside Roles(), so persona is consumed at first boot and gone
// from chain at the first drift commit, "leaving the path-driven roles as the
// durable form". This adapter translated half of it — system_prompt into
// APPEND_SYSTEM.md — and kept the inference pin in memory only. So the pin
// survived exactly until the first successful drift commit, after which every
// later boot came up with no model at all.
//
// models.json is the framework's native model configuration (docs/models.md),
// so making it a tracked role puts the pin where the framework already looks —
// the same shape as openclaw tracking its openclaw.json model/auth keys.
//
// It carries NO secret: the apiKey field holds the NAME of an environment
// variable, which the framework resolves at use time. That is what makes this
// role safe to anchor on chain.

// apiKeyEnvRef is the env var the models.json entry points at, rather than a
// literal key. Must match what spawnBridge exports.
const apiKeyEnvRef = "SEAL_MODEL_API_KEY"

type modelEntry struct {
	ID string `json:"id"`
}

type providerCfg struct {
	BaseURL    string          `json:"baseUrl"`
	API        string          `json:"api"`
	APIKey     string          `json:"apiKey"`
	AuthHeader bool            `json:"authHeader"`
	Compat     map[string]bool `json:"compat,omitempty"`
	Models     []modelEntry    `json:"models"`
}

type modelsConfig struct {
	Providers map[string]providerCfg `json:"providers"`
}

// buildModelsConfig renders the pin as the framework's model registration.
//
// compat disables the `developer` role and `reasoning_effort`: a third-party
// OpenAI-compatible endpoint generally understands neither, and the package's
// own docs recommend turning both off for that class of server.
func buildModelsConfig(provider, model, api, baseURL string) modelsConfig {
	return modelsConfig{Providers: map[string]providerCfg{
		provider: {
			BaseURL:    baseURL,
			API:        api,
			APIKey:     apiKeyEnvRef,
			AuthHeader: true,
			Compat:     map[string]bool{"supportsDeveloperRole": false, "supportsReasoningEffort": false},
			Models:     []modelEntry{{ID: model}},
		},
	}}
}

// canonicalModels re-marshals model config bytes deterministically (Go sorts
// map keys; struct fields marshal in declaration order), so the framework's own
// formatting never shows up as drift.
func canonicalModels(raw []byte) ([]byte, error) {
	var cfg modelsConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse models.json: %w", err)
	}
	if len(cfg.Providers) == 0 {
		return nil, nil
	}
	out, err := json.Marshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal models.json: %w", err)
	}
	return out, nil
}

// writeModelsJSON lands the pin on disk in canonical form.
func writeModelsJSON(cfg modelsConfig) error {
	if err := ensureDir(primeHome); err != nil {
		return err
	}
	b, err := json.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal models.json: %w", err)
	}
	if err := os.WriteFile(modelsJSONPath(), b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", modelsJSONPath(), err)
	}
	return nil
}

// readPin returns the provider/model this agent is pinned to, from the tracked
// models.json. Empty strings when there is no pin yet.
func readPin() (provider, model string) {
	raw, err := os.ReadFile(modelsJSONPath())
	if err != nil {
		return "", ""
	}
	var cfg modelsConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", ""
	}
	for name, p := range cfg.Providers {
		if len(p.Models) > 0 {
			return name, p.Models[0].ID
		}
		return name, ""
	}
	return "", ""
}

// evoModelsJSON returns the canonical plaintext for the role. A missing or
// provider-less file is "no content", matching Defaults.
func (a *Adapter) evoModelsJSON() ([]byte, error) {
	raw, err := os.ReadFile(modelsJSONPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("prime evoModelsJSON: read %s: %w", modelsJSONPath(), err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	out, err := canonicalModels(raw)
	if err != nil {
		return nil, fmt.Errorf("prime evoModelsJSON: %w", err)
	}
	return out, nil
}

// restoreModelsJSON lands the chain plaintext. nil means "chain has no entry":
// leave an existing file alone (a restart must not wipe a pin the agent is
// running on) but create nothing, so the absent-on-chain invariant holds.
func (a *Adapter) restoreModelsJSON(plaintext []byte) error {
	if len(bytes.TrimSpace(plaintext)) == 0 {
		return nil
	}
	canon, err := canonicalModels(plaintext)
	if err != nil {
		return fmt.Errorf("prime.Restore[models.json]: %w", err)
	}
	if err := ensureDir(primeHome); err != nil {
		return fmt.Errorf("prime.Restore[models.json]: %w", err)
	}
	if err := os.WriteFile(modelsJSONPath(), canon, 0o644); err != nil {
		return fmt.Errorf("prime.Restore[models.json]: write: %w", err)
	}
	return nil
}
