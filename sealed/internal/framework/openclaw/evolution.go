package openclaw

import (
	"context"
	"encoding/json"

	"seal-verify/internal/framework"
)

// EvolutionFor produces canonical iData plaintext bytes for `role` by
// reading the live state from disk: ~/.openclaw/openclaw.json + the
// workspace markdown files + skills / canvas subtrees. Reading from disk
// (rather than a stale in-memory cfg) is what makes evolution detection
// correct — when the agent self-modifies its config (dashboard upgrade,
// plugin install, MEMORY.md write), the watcher's next tick observes
// those changes.
//
// Output MUST be deterministic: same on-disk state → byte-identical
// output. Per-role helpers in evolution_paths.go enforce this through
// stable JSON marshalling and determinism-tar.
func (a *Adapter) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	switch role {
	case "framework":
		return a.evoFramework(ctx)
	case "openclaw.json":
		return a.evoOpenclawJSON()
	case "workspace/":
		return a.evoWorkspace()
	case "workspace/skills/":
		return a.evoWorkspaceSkills()
	case "workspace/canvas/":
		return a.evoWorkspaceCanvas()
	}
	return nil, framework.ErrUnsupportedDim
}

// evoFramework returns the framework binding plaintext (current openclaw
// name + npm package version + protocol schema version). Lives on the
// path-driven side because every role's evolution shares the same iData
// schema — see evolution_paths.go for the other four.
func (a *Adapter) evoFramework(ctx context.Context) ([]byte, error) {
	a.mu.RLock()
	fb := frameworkBinding{}
	if a.cfg != nil {
		fb = a.cfg.framework
	}
	a.mu.RUnlock()
	// Live-probe the installed openclaw npm version so a dashboard upgrade
	// is observable as drift on this role. Empty result means probe failed
	// (binary not installed yet — happens during pre-Start seed) so we
	// keep the cfg value.
	if v := probeOpenclawVersion(ctx); v != "" {
		fb.PackageVersion = v
	}
	return json.Marshal(&fb)
}
