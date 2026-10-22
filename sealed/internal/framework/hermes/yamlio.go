package hermes

import (
	"errors"
	"fmt"
	"io/fs"

	"gopkg.in/yaml.v3"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// YAML I/O for ~/.hermes/config.yaml.
//
// The file is a local artifact, not an iData role: RenderSettings rebuilds
// it from the owner's settings document at every Start and nothing captures
// it, so no canonical-JSON wire encoding and no secret strip are needed —
// the inference key it carries never leaves the container.

// loadConfigYAML reads and parses ~/.hermes/config.yaml. A missing file
// is an empty config. yaml.v3 unmarshals string-keyed mappings as
// map[string]any, which is directly json.Marshal-able.
//
// The file is agent-writable and untracked, and the render rewrites every
// key it owns, so a file that cannot be used for any reason — one the
// privsep read rules refuse (a link, a FIFO, a socket, a directory), one
// over its size limit, one that cannot be opened, one that does not parse —
// is reported as unusable, with an empty config: updateConfigYAML then sets
// the entry aside (setAsideConfig) and rebuilds the file. Failing instead
// would fail every framework start until a reset, over a file the agent
// can break.
func loadConfigYAML() (cfg map[string]any, unusable error) {
	raw, err := privsep.ReadFile(configYAMLPath(), privsep.LimitConfig)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return map[string]any{}, err
	}
	cfg = map[string]any{}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return map[string]any{}, fmt.Errorf("does not parse: %w", err)
	}
	if cfg == nil { // empty document parses to nil map
		cfg = map[string]any{}
	}
	return cfg, nil
}

// maxSetAside bounds the names setAsideConfig tries.
const maxSetAside = 10

// setAsideConfig moves an unusable config.yaml out of the way before the
// render rebuilds it, so what the agent kept there besides the keys the
// platform owns (MCP servers, toolsets, terminal settings, ...) is not lost
// with it: to config.yaml.corrupt, or the first free config.yaml.corrupt-N.
// The rename moves the entry itself (a link, a directory, whatever is
// there), follows no link and replaces nothing (privsep.RenameNoReplace).
// When all maxSetAside names are taken, the newest copy still goes aside:
// it replaces config.yaml.corrupt-<maxSetAside> (whatever is there), so the
// copy the agent is told to recover from is never the one lost. Only when
// that rename fails too is the rebuilt file written over the entry
// (privsep.WriteFile replaces whatever is at the name).
func setAsideConfig(why error) {
	path := configYAMLPath()
	last := ""
	for i := 1; i <= maxSetAside; i++ {
		last = path + ".corrupt"
		if i > 1 {
			last = fmt.Sprintf("%s.corrupt-%d", path, i)
		}
		err := privsep.RenameNoReplace(path, last)
		switch {
		case err == nil:
			logger.Logf("hermes: %s is unusable (%v); moved to %s and rebuilding it from the owner's settings", path, why, last)
			return
		case errors.Is(err, fs.ErrExist):
			continue
		case errors.Is(err, fs.ErrNotExist):
			return // gone meanwhile: nothing to keep
		default:
			logger.Logf("hermes: %s is unusable (%v) and could not be set aside (%v); rebuilding it from the owner's settings", path, why, err)
			return
		}
	}
	err := privsep.Rename(path, last)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// A directory at the name blocks the rename: it holds only the
		// newest copy, so clear it and retry.
		if rerr := privsep.RemoveAll(last); rerr == nil {
			err = privsep.Rename(path, last)
		}
	}
	if err != nil {
		logger.Logf("hermes: %s is unusable (%v), %s.corrupt through .corrupt-%d are all taken, and it could not replace the last (%v); rebuilding it over the unusable copy", path, why, path, maxSetAside, err)
		return
	}
	logger.Logf("hermes: %s is unusable (%v); %s.corrupt through .corrupt-%d are all taken, so it replaced %s; rebuilding it from the owner's settings", path, why, path, maxSetAside, last)
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
	cfg, unusable := loadConfigYAML()
	if unusable != nil {
		setAsideConfig(unusable)
	}
	mutate(cfg)
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config.yaml: %w", err)
	}
	if err := privsep.MkdirAll(hermesHome, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", hermesHome, err)
	}
	if err := privsep.WriteFile(configYAMLPath(), out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", configYAMLPath(), err)
	}
	return nil
}
