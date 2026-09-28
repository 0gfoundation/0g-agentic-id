package hermes

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// YAML I/O for ~/.hermes/config.yaml.
//
// The file is a local artifact, not an iData role: RenderSettings rebuilds
// it from the owner's settings document at every Start and nothing captures
// it, so no canonical-JSON wire encoding and no secret strip are needed —
// the inference key it carries never leaves the container.

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
// (0600 — RenderSettings writes the literal inference key into model.api_key,
// which is the only place hermes's `custom` provider reads it from). Creates
// hermesHome as needed.
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
