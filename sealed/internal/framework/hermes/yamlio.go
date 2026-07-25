package hermes

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// YAML I/O for ~/.hermes/config.yaml.
//
// The iData wire encoding for the "config.yaml" role is canonical JSON
// (compact, sorted keys — encoding/json's map marshalling), NOT YAML:
// YAML serialization is not deterministic enough to hash, and the chain
// payload must be. The adapter converts at the edge — YAML on disk for
// hermes, JSON on chain for the watcher/uploader.

// loadConfigYAML reads and parses ~/.hermes/config.yaml. A missing file
// is an empty config, not an error. yaml.v3 unmarshals string-keyed
// mappings as map[string]any, which is directly json.Marshal-able.
func loadConfigYAML() (map[string]any, error) {
	raw, err := os.ReadFile(configYAMLPath())
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", configYAMLPath(), err)
	}
	cfg := map[string]any{}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configYAMLPath(), err)
	}
	if cfg == nil { // empty document parses to nil map
		cfg = map[string]any{}
	}
	return cfg, nil
}

// updateConfigYAML loads config.yaml, applies mutate, writes it back
// (0600 — hermes may keep an api_key in it if the agent self-configures
// one, see stripSecrets). Creates hermesHome as needed.
//
// Comments in the on-disk file are NOT preserved across an update (we
// re-marshal from the parsed map). Acceptable: the installer's commented
// template is documentation, and hermes itself reads values only.
func updateConfigYAML(mutate func(cfg map[string]any)) error {
	cfg, err := loadConfigYAML()
	if err != nil {
		return err
	}
	mutate(cfg)
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config.yaml: %w", err)
	}
	if err := os.MkdirAll(hermesHome, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", hermesHome, err)
	}
	if err := os.WriteFile(configYAMLPath(), out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", configYAMLPath(), err)
	}
	return nil
}

// stripSecrets recursively deletes every key named "api_key" from
// string-keyed maps (descending into nested maps and slices). Run
// unconditionally on the capture path: our own policy injects inference
// keys via env at spawn (never disk), but the agent itself can run
// `hermes config set model.api_key ...`, which writes the key into
// config.yaml — verified live. Without this strip that key would be
// sealed into iData. Deleting deterministically also means the strip
// itself never produces phantom drift.
func stripSecrets(v any) {
	switch t := v.(type) {
	case map[string]any:
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
