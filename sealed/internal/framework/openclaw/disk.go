package openclaw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ── openclaw.json merge I/O ─────────────────────────────────────────────────
//
// Multiple Restore calls + Start all write into the same openclaw.json.
// Each writer owns specific top-level keys; we read-merge-write rather
// than rewriting the whole file so dim writes don't clobber each other.

// loadOpenclawJSON parses ~/.openclaw/openclaw.json, returning an empty
// map if the file doesn't exist.
func loadOpenclawJSON() (map[string]any, error) {
	data, err := os.ReadFile(openclawJSONPath())
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", openclawJSONPath(), err)
	}
	var cfg map[string]any
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", openclawJSONPath(), err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

// saveOpenclawJSON writes ~/.openclaw/openclaw.json with stable indent.
// Creates the home dir when missing.
func saveOpenclawJSON(cfg map[string]any) error {
	if err := os.MkdirAll(openclawHome, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", openclawHome, err)
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal openclaw.json: %w", err)
	}
	if err := os.WriteFile(openclawJSONPath(), out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", openclawJSONPath(), err)
	}
	return nil
}

// updateOpenclawJSON loads, applies a transform, and saves. Convenience
// wrapper for the read-merge-write pattern every Restore uses.
func updateOpenclawJSON(transform func(cfg map[string]any)) error {
	cfg, err := loadOpenclawJSON()
	if err != nil {
		return err
	}
	transform(cfg)
	return saveOpenclawJSON(cfg)
}

// setSection is a small helper that assigns a top-level key, treating an
// empty `json.RawMessage` (or an explicit JSON null) as "delete the key".
// This keeps the round-trip stable: an attestor producing `{}` for a dim
// shouldn't leave stale content from a previous Restore in openclaw.json.
func setSection(cfg map[string]any, key string, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		delete(cfg, key)
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("section %s parse: %w", key, err)
	}
	cfg[key] = v
	return nil
}

// section reads a top-level key as json.RawMessage. Missing key returns
// empty (omitted on serialize) rather than nil to keep round-trip stable.
func section(cfg map[string]any, key string) json.RawMessage {
	v, ok := cfg[key]
	if !ok || v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// agentsDefaultsSection extracts a sub-key under `agents.defaults`. Used
// by skills (skills list) and ops (rateLimits, safety) which all live
// under that namespace.
func agentsDefaultsSection(cfg map[string]any, subKey string) json.RawMessage {
	agents, ok := cfg["agents"].(map[string]any)
	if !ok {
		return nil
	}
	defaults, ok := agents["defaults"].(map[string]any)
	if !ok {
		return nil
	}
	v, ok := defaults[subKey]
	if !ok || v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// setAgentsDefaults assigns a sub-key under `agents.defaults`. Creates
// nested maps as needed. Empty raw deletes.
func setAgentsDefaults(cfg map[string]any, subKey string, raw json.RawMessage) error {
	agents, ok := cfg["agents"].(map[string]any)
	if !ok {
		agents = map[string]any{}
		cfg["agents"] = agents
	}
	defaults, ok := agents["defaults"].(map[string]any)
	if !ok {
		defaults = map[string]any{}
		agents["defaults"] = defaults
	}
	if len(raw) == 0 || string(raw) == "null" {
		delete(defaults, subKey)
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("agents.defaults.%s parse: %w", subKey, err)
	}
	defaults[subKey] = v
	return nil
}

// ── workspace file I/O ─────────────────────────────────────────────────────

func writeWorkspaceFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// readWorkspaceFile returns "" if the file is missing — agent may not
// have created it yet, or it was never seeded.
func readWorkspaceFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
