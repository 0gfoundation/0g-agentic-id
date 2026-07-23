package hermes

import (
	"context"
	"encoding/json"

	"seal-verify/internal/framework"
)

// EvolutionFor produces canonical iData plaintext bytes for `role` by
// reading the live state from disk: ~/.hermes/config.yaml + SOUL.md +
// memories/ + skills/. Reading from disk (rather than a stale in-memory
// cfg) is what makes evolution detection correct — when the agent
// self-modifies (config set, memory write, learned skill), the watcher's
// next tick observes it.
//
// Output MUST be deterministic: same on-disk state → byte-identical
// output. Per-role helpers in evolution_paths.go enforce this through
// stable JSON marshalling and determinism-tar.
func (a *Adapter) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	switch role {
	case "framework":
		return a.evoFramework(ctx)
	case "config.yaml":
		return a.evoConfigYAML()
	case "SOUL.md":
		return a.evoSoulMD()
	case "memories/":
		return a.evoMemories()
	case "skills/":
		return a.evoSkills()
	}
	return nil, framework.ErrUnsupportedDim
}

// evoFramework returns the framework binding plaintext. Live-probes the
// installed hermes version so a self-upgrade is observable as drift on
// this role. Empty probe result (binary not installed yet — happens
// during pre-Start seed) keeps the cfg value.
func (a *Adapter) evoFramework(ctx context.Context) ([]byte, error) {
	a.mu.RLock()
	fb := frameworkBinding{}
	if a.cfg != nil {
		fb = a.cfg.framework
	}
	a.mu.RUnlock()
	if v := probeHermesVersion(ctx); v != "" {
		fb.PackageVersion = v
	}
	return json.Marshal(&fb)
}
